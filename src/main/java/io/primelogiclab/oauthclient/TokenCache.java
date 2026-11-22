package io.primelogiclab.oauthclient;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Expiry;
import com.github.benmanes.caffeine.cache.Ticker;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Access tokens per (service, tenant, scope set), reused until shortly before they expire. At most one renewal per
 * key runs at a time: while it runs, other threads get the current token if it hasn't expired yet, or
 * else wait for the renewal and share its result or its failure, so a failing token endpoint gets one
 * request, not one per thread. Expired tokens are evicted. Thread-safe.
 *
 * <p>A token whose expiry is unknown (no JWT {@code exp}, no {@code expires_in}, no introspection) is
 * kept until the service rejects it: {@link #renew(ClientInfo, AccessToken, TokenFetcher)}.
 *
 * <p>The renewing thread fetches on its own thread, so its timeouts and interrupts apply. Renewal isn't
 * done inside the Caffeine map's {@code compute}: a slow token request there would block other keys.
 *
 * <p>After a failed token request no other is sent for the key for {@link #FIRST_RETRY_DELAY}, doubled with
 * each further failure in a row, up to the client info's {@link ClientInfo#getMaxTokenRetryDelay() ceiling},
 * and at least as long as the token server's Retry-After within it; so a failure that won't fix itself
 * doesn't use up a vendor's cap on token requests. Meanwhile callers get the current token while it hasn't
 * expired, else the last failure at once. The wait holds only for the same token settings and credentials,
 * so a fixed configuration is tried at once; a success ends it.
 */
final class TokenCache {

    /**
     * A token is renewed this long before it expires, so it isn't sent when it's about to expire and
     * the call made twice; a token that lives less than twice this is renewed at half its lifetime.
     */
    static final Duration RENEWAL_MARGIN = Duration.ofMinutes(5);
    /** Most (service, tenant) entries kept; a bound on memory, far above the expected number. */
    static final long MAXIMUM_SIZE = 10000;
    /** The wait after the first failed token request in a row; doubled for each further one. */
    static final Duration FIRST_RETRY_DELAY = Duration.ofSeconds(5);

    private static final Logger LOG = Logger.getLogger(TokenCache.class.getName());

    private final Clock clock;
    private final Cache<Key, Entry> cache;
    private final ConcurrentMap<Key, Renewal> renewals = new ConcurrentHashMap<Key, Renewal>();
    /** The last failed token request per key; dropped on success, and after the longest possible wait. */
    private final Cache<Key, Failure> failures;

    TokenCache() {
        this(Clock.systemUTC(), Ticker.systemTicker(), null, MAXIMUM_SIZE);
    }

    /** @param executor runs Caffeine's maintenance; {@code null} for its default */
    TokenCache(Clock clock, Ticker ticker, Executor executor, long maximumSize) {
        this.clock = clock;
        Caffeine<Object, Object> builder = Caffeine.newBuilder().ticker(ticker).maximumSize(maximumSize);
        if (executor != null) {
            builder.executor(executor);
        }
        this.cache = builder.expireAfter(new UntilTokenExpiry()).build();
        Caffeine<Object, Object> failuresBuilder = Caffeine.newBuilder().ticker(ticker).maximumSize(maximumSize)
                .expireAfterWrite(ClientInfo.MAX_TOKEN_RETRY_DELAY_LIMIT.toNanos(), TimeUnit.NANOSECONDS);
        if (executor != null) {
            failuresBuilder.executor(executor);
        }
        this.failures = failuresBuilder.build();
    }

    /** {@link #get(ClientInfo, List, TokenFetcher)} with the client info's default scopes. */
    AccessToken get(ClientInfo clientInfo, TokenFetcher fetcher) {
        return get(clientInfo, null, fetcher);
    }

    /**
     * The cached token while it's fresh enough, else a new one from {@code fetcher}.
     *
     * @param requestedScopes the app's scopes for this request; {@code null} or empty for the client info's defaults
     * @throws IllegalArgumentException if a requested scope is blank or contains spaces
     */
    AccessToken get(ClientInfo clientInfo, List<String> requestedScopes, TokenFetcher fetcher) {
        List<String> scopes = clientInfo.effectiveScopes(requestedScopes);
        Key key = Key.of(clientInfo, scopes);
        List<Object> settings = clientInfo.tokenSettings();
        while (true) {
            AccessToken current = cached(key, settings);
            if (current != null && isUsable(current)) {
                return current;
            }
            Failure failure = coolingDown(key, clientInfo, settings);
            if (failure != null) {
                if (current != null && !isExpired(current)) {
                    return current; // still good while no new one may be asked for
                }
                throw heldBack(key, failure);
            }
            Renewal mine = new Renewal(settings);
            Renewal running = renewals.putIfAbsent(key, mine);
            if (running == null) {
                return fetch(key, clientInfo, scopes, fetcher, mine, current, null);
            }
            if (current != null && !isExpired(current)) {
                return current; // another thread renews it; this one still works meanwhile
            }
            AccessToken shared = await(running, settings);
            if (shared != null && running.settings.equals(settings)) {
                return shared;
            }
            // that renewal was for other settings, or its thread was interrupted: look again
        }
    }

    /** {@link #renew(ClientInfo, List, AccessToken, TokenFetcher)} with the client info's default scopes. */
    AccessToken renew(ClientInfo clientInfo, AccessToken rejected, TokenFetcher fetcher) {
        return renew(clientInfo, null, rejected, fetcher);
    }

    /**
     * A new token after the service rejected {@code rejected} (answered 401). The rejected token is
     * dropped. If another thread already replaced it, that token is returned without another request.
     *
     * @param requestedScopes the scopes {@code rejected} was asked for, as passed to {@link #get(ClientInfo, List, TokenFetcher)}
     */
    AccessToken renew(ClientInfo clientInfo, List<String> requestedScopes, AccessToken rejected, TokenFetcher fetcher) {
        Objects.requireNonNull(rejected, "rejected");
        List<String> scopes = clientInfo.effectiveScopes(requestedScopes);
        Key key = Key.of(clientInfo, scopes);
        List<Object> settings = clientInfo.tokenSettings();
        Entry entry = cache.getIfPresent(key);
        if (entry != null && sameValue(entry.token, rejected)) {
            cache.asMap().remove(key, entry);
        }
        while (true) {
            AccessToken current = cached(key, settings);
            if (current != null && !sameValue(current, rejected) && !isExpired(current)) {
                return current;
            }
            Failure failure = coolingDown(key, clientInfo, settings);
            if (failure != null) {
                throw heldBack(key, failure);
            }
            Renewal mine = new Renewal(settings);
            Renewal running = renewals.putIfAbsent(key, mine);
            if (running == null) {
                return fetch(key, clientInfo, scopes, fetcher, mine, null, rejected);
            }
            AccessToken shared = await(running, settings);
            if (shared != null && running.settings.equals(settings) && !sameValue(shared, rejected)) {
                return shared;
            }
        }
    }

    /** Entries held now, after evicting expired ones; for tests. */
    long size() {
        cache.cleanUp();
        return cache.estimatedSize();
    }

    /**
     * Runs the renewal this thread claimed. If it fails while {@code fallback} hasn't expired, the
     * fallback is returned and the failure logged; threads waiting on the renewal get the failure. A
     * failed token request is recorded before the claim is released, so no other thread sends one meanwhile.
     */
    private AccessToken fetch(Key key, ClientInfo clientInfo, List<String> scopes, TokenFetcher fetcher,
                              Renewal mine, AccessToken fallback, AccessToken rejected) {
        OAuthServiceException held = null;
        try {
            // another renewal may have finished, or failed, between the cache lookup and claiming this one
            AccessToken latest = cached(key, mine.settings);
            if (latest != null && isUsable(latest) && !sameValue(latest, rejected)) {
                finish(key, mine, latest);
                return latest;
            }
            Failure failure = coolingDown(key, clientInfo, mine.settings);
            if (failure != null) {
                held = heldBack(key, failure);
                throw held;
            }
            AccessToken fresh = fetcher.fetch(clientInfo, scopes);
            if (fresh == null) {
                throw new IllegalStateException("The token fetcher returned no token");
            }
            cache.put(key, new Entry(fresh, mine.settings));
            failures.invalidate(key);
            finish(key, mine, fresh);
            return fresh;
        } catch (RuntimeException | Error e) {
            boolean interrupted = Thread.currentThread().isInterrupted();
            Failure recorded = null;
            if (e != held && e instanceof OAuthServiceException && !interrupted) {
                recorded = record(key, clientInfo, mine.settings, (OAuthServiceException) e);
            }
            renewals.remove(key, mine);
            if (interrupted) {
                mine.result.complete(null); // not the server's failure: the waiting threads try themselves
            } else {
                mine.result.completeExceptionally(e);
            }
            String next = recorded == null ? "" : "; no other request before " + recorded.until;
            if (e instanceof RuntimeException && fallback != null && !isExpired(fallback)) {
                if (e != held) {
                    LOG.log(Level.WARNING, "Token renewal for {0} failed; using the current token until it expires at {1}{2}: {3}",
                            new Object[] {key, fallback.getExpiresAt(), next, describe(e)});
                }
                return fallback;
            }
            if (recorded != null) {
                LOG.log(Level.WARNING, "Token request for {0} failed ({1} in a row){2}: {3}",
                        new Object[] {key, recorded.count, next, describe(e)});
            }
            throw e;
        }
    }

    /**
     * The failure {@code clientInfo} is still waiting out for {@code key}: recorded for the same token settings
     * and credentials, with its wait not over; else {@code null}.
     */
    private Failure coolingDown(Key key, ClientInfo clientInfo, List<Object> settings) {
        Failure failure = failures.getIfPresent(key);
        if (failure == null || !clock.instant().isBefore(failure.until) || !failure.settings.equals(settings)
                || !failure.fingerprint.equals(clientInfo.credentialsFingerprint())) {
            return null;
        }
        return failure;
    }

    /**
     * Records a failed token request: the wait is {@link #FIRST_RETRY_DELAY} doubled for each earlier failure
     * in a row for the same settings and credentials, at least the server's Retry-After, at most the client
     * info's ceiling. {@code null} when the client info turned the wait off.
     */
    private Failure record(Key key, ClientInfo clientInfo, List<Object> settings, OAuthServiceException e) {
        Duration ceiling = clientInfo.getMaxTokenRetryDelay();
        if (ceiling.isZero()) {
            failures.invalidate(key);
            return null;
        }
        String fingerprint = clientInfo.credentialsFingerprint();
        Failure previous = failures.getIfPresent(key);
        int count = previous != null && previous.settings.equals(settings) && previous.fingerprint.equals(fingerprint)
                ? previous.count + 1 : 1;
        Duration wait = retryDelay(count, ceiling);
        if (e.retryAfter() != null && e.retryAfter().compareTo(wait) > 0) {
            wait = e.retryAfter().compareTo(ceiling) > 0 ? ceiling : e.retryAfter();
        }
        Failure failure = new Failure(settings, fingerprint, e, count, clock.instant().plus(wait));
        failures.put(key, failure);
        return failure;
    }

    /** {@link #FIRST_RETRY_DELAY} doubled for each failure in a row after the first, at most {@code ceiling}. */
    static Duration retryDelay(int failuresInARow, Duration ceiling) {
        // 2^20 times 5 s is far beyond the 24-hour limit, and keeps the shift from overflowing
        Duration wait = FIRST_RETRY_DELAY.multipliedBy(1L << Math.min(Math.max(failuresInARow - 1, 0), 20));
        return wait.compareTo(ceiling) > 0 ? ceiling : wait;
    }

    /** The failure that holds back another token request, with its OAuth error, status and cause. */
    private static OAuthServiceException heldBack(Key key, Failure failure) {
        OAuthServiceException last = failure.last;
        return new OAuthServiceException("No token request for " + key + " before " + failure.until + " after "
                + (failure.count == 1 ? "a failed one" : failure.count + " failed ones in a row") + "; the last: "
                + last.getMessage(), last.getError(), last.getErrorDescription(), last.getErrorUri(),
                last.getHttpStatus(), last);
    }

    /** Out of the in-progress map first, so a woken waiter finds the cache updated, not this renewal again. */
    private void finish(Key key, Renewal renewal, AccessToken token) {
        renewals.remove(key, renewal);
        renewal.result.complete(token);
    }

    /**
     * The renewal's token; {@code null} when its thread was interrupted, or when it failed for other
     * settings than {@code settings}: that failure belongs to another configuration, so the caller tries
     * with its own. A failure for the same settings is thrown as is.
     */
    private static AccessToken await(Renewal renewal, List<Object> settings) {
        try {
            return renewal.result.get();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new OAuthServiceException("Interrupted while waiting for another thread's token request", e);
        } catch (ExecutionException e) {
            if (!renewal.settings.equals(settings)) {
                return null;
            }
            Throwable cause = e.getCause();
            if (cause instanceof RuntimeException) {
                throw (RuntimeException) cause;
            }
            if (cause instanceof Error) {
                throw (Error) cause;
            }
            throw new IllegalStateException(cause);
        }
    }

    private AccessToken cached(Key key, List<Object> settings) {
        Entry entry = cache.getIfPresent(key);
        return entry != null && entry.settings.equals(settings) ? entry.token : null;
    }

    /** Not within the renewal margin of expiry; for a short-lived token the margin is half its lifetime. */
    private boolean isUsable(AccessToken token) {
        if (token.getExpiresAt() == null) {
            return true;
        }
        Duration margin = RENEWAL_MARGIN;
        Duration half = Duration.between(token.getIssuedAt(), token.getExpiresAt()).dividedBy(2);
        if (!half.isNegative() && half.compareTo(margin) < 0) {
            margin = half;
        }
        return !token.isExpired(clock.instant(), margin);
    }

    private boolean isExpired(AccessToken token) {
        return token.isExpired(clock.instant(), Duration.ZERO);
    }

    private static boolean sameValue(AccessToken a, AccessToken b) {
        return a != null && b != null && a.getValue().equals(b.getValue());
    }

    private static String describe(Throwable e) {
        return e.getClass().getSimpleName() + (e.getMessage() == null ? "" : ": " + Strings.safe(e.getMessage()));
    }

    /** Evicts an entry when its token expires; one whose expiry is unknown stays until renewed or crowded out. */
    private final class UntilTokenExpiry implements Expiry<Key, Entry> {

        @Override
        public long expireAfterCreate(Key key, Entry entry, long currentTime) {
            return nanosUntilExpiry(entry.token);
        }

        @Override
        public long expireAfterUpdate(Key key, Entry entry, long currentTime, long currentDuration) {
            return nanosUntilExpiry(entry.token);
        }

        @Override
        public long expireAfterRead(Key key, Entry entry, long currentTime, long currentDuration) {
            return currentDuration;
        }

        private long nanosUntilExpiry(AccessToken token) {
            if (token.getExpiresAt() == null) {
                return Long.MAX_VALUE;
            }
            Duration left = Duration.between(clock.instant(), token.getExpiresAt());
            if (left.isNegative()) {
                return 0;
            }
            try {
                return left.toNanos();
            } catch (ArithmeticException tooLong) {
                return Long.MAX_VALUE;
            }
        }
    }

    /**
     * Service, tenant, user and scope set. A {@code null} tenant is global, so it never matches a tenant
     * coded {@code GLOBAL}. The user is the subject of a JWT bearer or refresh token grant, so one user
     * never gets another user's token; it is {@code null} for client credentials, whose token serves the
     * whole tenant. The scopes are a set, so the same scopes in another order share a token, while tokens
     * for different scopes are kept side by side instead of replacing each other.
     */
    static final class Key {

        private final String service;
        private final String tenant;
        private final String user;
        private final Set<String> scopes;

        private Key(String service, String tenant, String user, Set<String> scopes) {
            this.service = service;
            this.tenant = tenant;
            this.user = user;
            this.scopes = scopes;
        }

        static Key of(ClientInfo clientInfo, List<String> scopes) {
            return new Key(clientInfo.getService(), clientInfo.getTenant(), clientInfo.cacheUser(),
                    Collections.unmodifiableSet(new TreeSet<String>(scopes)));
        }

        @Override
        public boolean equals(Object o) {
            if (!(o instanceof Key)) {
                return false;
            }
            Key k = (Key) o;
            return service.equals(k.service) && Objects.equals(tenant, k.tenant) && Objects.equals(user, k.user)
                    && scopes.equals(k.scopes);
        }

        @Override
        public int hashCode() {
            return ((31 * service.hashCode() + Objects.hashCode(tenant)) * 31 + Objects.hashCode(user)) * 31
                    + scopes.hashCode();
        }

        /** Service, tenant and scopes; the user only as "(a user)", since a user ID or username is personal data. */
        @Override
        public String toString() {
            return Strings.safe((tenant == null ? service + " (global)" : service + "/" + tenant)
                    + (user == null ? "" : " (a user)")
                    + (scopes.isEmpty() ? "" : " " + scopes));
        }
    }

    /** A cached token and the client info settings it was obtained with. */
    private static final class Entry {

        final AccessToken token;
        final List<Object> settings;

        Entry(AccessToken token, List<Object> settings) {
            this.token = token;
            this.settings = settings;
        }
    }

    /** A failed token request: for which settings and credentials, how many in a row, and until when it holds. */
    private static final class Failure {

        final List<Object> settings;
        final String fingerprint;
        final OAuthServiceException last;
        final int count;
        final Instant until;

        Failure(List<Object> settings, String fingerprint, OAuthServiceException last, int count, Instant until) {
            this.settings = settings;
            this.fingerprint = fingerprint;
            this.last = last;
            this.count = count;
            this.until = until;
        }
    }

    /** A renewal in progress, which waiting threads share. */
    private static final class Renewal {

        final List<Object> settings;
        final CompletableFuture<AccessToken> result = new CompletableFuture<AccessToken>();

        Renewal(List<Object> settings) {
            this.settings = settings;
        }
    }
}
