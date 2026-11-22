package io.primelogiclab.oauthclient;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Supplier;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Authorization server metadata (RFC 8414, OpenID Connect Discovery) for client infos that give an issuer or a
 * metadata URL instead of a token URL, read once and kept for {@link #TTL}, shared by the whole JVM (per class
 * loader). One read per document at a time: while it runs, other threads use the document they have, or wait
 * for it. If a refresh fails, the document already held stays in use, so a metadata outage doesn't stop token
 * requests. Thread-safe.
 *
 * <p>Brought over from oauth-connector's {@code MetadataResolver}, which stays as it is.
 */
final class MetadataCache {

    /** How long a document is used before it is read again. */
    static final Duration TTL = Duration.ofHours(24);
    /** Largest document read, in bytes; real ones are a few kilobytes. */
    static final int MAX_DOCUMENT_BYTES = 256 * 1024;
    static final String OIDC_SUFFIX = "/.well-known/openid-configuration";
    static final String OAUTH_SUFFIX = "/.well-known/oauth-authorization-server";
    /** Most documents kept; a bound on memory, far above the expected number of token servers. */
    private static final long MAXIMUM_SIZE = 10000;
    /** Most characters of a value from the document put in a message. */
    private static final int MAX_SHOWN = 200;

    /** The JVM-wide metadata, which every token client uses. */
    static final MetadataCache SHARED = new MetadataCache(Clock.systemUTC());

    private static final Logger LOG = Logger.getLogger(MetadataCache.class.getName());

    private final Clock clock;
    private final Cache<String, Slot> slots = Caffeine.newBuilder().maximumSize(MAXIMUM_SIZE).build();

    MetadataCache(Clock clock) {
        this.clock = clock;
    }

    /**
     * The metadata for the client info's issuer or metadata URL, read through {@code http} when there is none
     * yet or it is older than {@link #TTL}.
     *
     * @throws OAuthServiceException if no usable document could be read and none is held
     */
    ServerMetadata resolve(ClientInfo info, HttpExecutor http) {
        Slot slot = slots.get(info.getIssuer() + " " + info.getMetadataUrl(), k -> new Slot());
        Instant now = clock.instant();
        long seen = slot.attempts;
        ServerMetadata current = slot.document;
        if (current != null && fresh(slot, now)) {
            return current;
        }
        if (current != null) {
            if (!slot.lock.tryLock()) {
                return current; // another thread reads it again; this one carries on with what it has
            }
        } else {
            try {
                slot.lock.lockInterruptibly();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new OAuthServiceException("Interrupted while waiting for the authorization server metadata", e);
            }
        }
        try {
            if (slot.document != null && fresh(slot, now)) {
                return slot.document; // read by another thread meanwhile
            }
            OAuthServiceException failure = slot.lastFailure;
            if (slot.document == null && slot.attempts != seen && failure != null) {
                // another thread has just tried and failed: don't send the same requests again at once
                throw new OAuthServiceException(failure.getMessage(), failure.getError(), failure.getErrorDescription(),
                        failure.getErrorUri(), failure.getHttpStatus(), failure.retryAfter(), failure);
            }
            try {
                ServerMetadata read = read(info, http);
                slot.document = read;
                slot.readAt = now;
                slot.lastFailure = null;
                return read;
            } catch (OAuthServiceException e) {
                if (interrupted(e)) {
                    slot.lastFailure = null; // the caller was cancelled: not the server's failure
                    throw e;
                }
                slot.lastFailure = e;
                if (slot.document != null) {
                    LOG.log(Level.WARNING, "Reading the authorization server metadata for {0} failed; using the copy "
                            + "read at {1} for another {2}: {3}", new Object[] {info.label(), slot.readAt, TTL,
                            Strings.safe(e.getMessage())});
                    slot.readAt = now; // don't ask again before the next period
                    return slot.document;
                }
                throw e;
            } finally {
                slot.attempts++;
            }
        } finally {
            slot.lock.unlock();
        }
    }

    private static boolean fresh(Slot slot, Instant now) {
        Instant at = slot.readAt;
        return at != null && now.isBefore(at.plus(TTL));
    }

    /** The first usable document among the candidate URLs; a document that answers but is wrong fails at once. */
    private ServerMetadata read(ClientInfo info, HttpExecutor http) {
        List<String> failures = new ArrayList<String>();
        for (final String url : candidateUrls(info)) {
            HttpResponse response;
            try {
                response = http.execute(new Supplier<HttpRequest>() {
                    @Override
                    public HttpRequest get() {
                        Map<String, String> headers = new LinkedHashMap<String, String>();
                        headers.put("Accept", "application/json");
                        return HttpRequest.get(url, headers).withMaxResponseBytes(MAX_DOCUMENT_BYTES);
                    }
                }, HttpExecutor.Retry.IF_NOT_PROCESSED);
            } catch (OAuthServiceException e) {
                if (interrupted(e)) {
                    throw e;
                }
                // no answer at all: the other well-known URLs are on the same server, so they'd only wait as long
                failures.add(HttpRequest.redactUrl(url) + " -> " + Strings.safe(e.getMessage()));
                break;
            }
            if (!response.isSuccessful()) {
                failures.add(HttpRequest.redactUrl(url) + " -> HTTP " + response.getStatus());
                continue;
            }
            Map<String, Object> document;
            try {
                document = Json.parseObject(response.getBody());
            } catch (IllegalArgumentException e) {
                failures.add(HttpRequest.redactUrl(url) + " -> not a JSON object");
                continue;
            }
            ServerMetadata metadata = ServerMetadata.from(url, document);
            check(info, metadata);
            LOG.log(Level.FINE, "Read the authorization server metadata for {0} from {1}",
                    new Object[] {info.label(), HttpRequest.redactUrl(url)});
            return metadata;
        }
        throw new OAuthServiceException("Couldn't read the authorization server metadata for " + info.label() + ": "
                + failures);
    }

    /**
     * Refuses a document that names another issuer (RFC 8414 section 3.3, OpenID Connect Discovery 4.3), or whose
     * token endpoints aren't https URLs without user info.
     */
    private static void check(ClientInfo info, ServerMetadata metadata) {
        String source = HttpRequest.redactUrl(metadata.sourceUrl());
        String expected = info.getIssuer();
        String actual = metadata.issuer();
        if (expected != null && !expected.equals(actual)) {
            throw new OAuthServiceException("The metadata at " + source + " names the issuer " + shown(actual)
                    + ", not " + expected + slashHint(expected, actual));
        }
        if (metadata.tokenEndpoint() == null) {
            throw new OAuthServiceException("The metadata at " + source + " has no token_endpoint");
        }
        String problem = ClientInfo.urlProblem(metadata.tokenEndpoint());
        if (problem != null) {
            throw new OAuthServiceException("The metadata at " + source + " declares a token_endpoint that " + problem);
        }
        if (metadata.mtlsTokenEndpoint() != null) {
            String mtlsProblem = ClientInfo.urlProblem(metadata.mtlsTokenEndpoint());
            if (mtlsProblem != null) {
                throw new OAuthServiceException("The metadata at " + source
                        + " declares an mtls_endpoint_aliases.token_endpoint that " + mtlsProblem);
            }
        }
    }

    /** Issuers must match exactly; points out the usual near miss, a trailing slash. */
    static String slashHint(String expected, String actual) {
        return actual != null && stripSlash(expected).equals(stripSlash(actual))
                ? " (issuers must match exactly, trailing slash included: set the issuer to " + shown(actual) + ")" : "";
    }

    /**
     * The metadata URL when one is set; else the well-known locations of the issuer, in this order: OpenID Connect
     * ({@code issuer + /.well-known/openid-configuration}), RFC 8414 (the well-known segment before the issuer's
     * path) and the appended RFC 8414 form some servers use.
     */
    static List<String> candidateUrls(ClientInfo info) {
        List<String> urls = new ArrayList<String>();
        if (info.getMetadataUrl() != null) {
            urls.add(info.getMetadataUrl());
            return urls;
        }
        String issuer = stripSlash(info.getIssuer());
        urls.add(issuer + OIDC_SUFFIX);
        try {
            URI u = new URI(issuer);
            String path = u.getRawPath() == null ? "" : u.getRawPath();
            String rfc8414 = u.getScheme() + "://" + u.getRawAuthority() + OAUTH_SUFFIX + path;
            if (!urls.contains(rfc8414)) {
                urls.add(rfc8414);
            }
        } catch (URISyntaxException e) {
            throw new IllegalStateException(e); // ClientInfo.build() checked the issuer
        }
        String appended = issuer + OAUTH_SUFFIX;
        if (!urls.contains(appended)) {
            urls.add(appended);
        }
        return urls;
    }

    private static String stripSlash(String s) {
        return s.endsWith("/") ? s.substring(0, s.length() - 1) : s;
    }

    private static String shown(String value) {
        if (value == null) {
            return "(none)";
        }
        String s = Strings.safe(value);
        return s.length() <= MAX_SHOWN ? s : s.substring(0, MAX_SHOWN) + "...";
    }

    private static boolean interrupted(Throwable e) {
        for (Throwable c = e; c != null; c = c.getCause()) {
            if (c instanceof InterruptedException) {
                return true;
            }
        }
        return Thread.currentThread().isInterrupted();
    }

    /** One document's state; its fields are written only under the lock. */
    private static final class Slot {

        final ReentrantLock lock = new ReentrantLock();
        volatile ServerMetadata document;
        volatile Instant readAt;
        /** Reads tried so far, and the last one's failure ({@code null} after a success). */
        volatile long attempts;
        volatile OAuthServiceException lastFailure;
    }
}
