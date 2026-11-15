package io.primelogiclab.oauthclient;

import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.Supplier;

/**
 * Calls one OAuth-protected service for backend code: it gets the access token for the {@link ClientInfo}
 * given to {@link #initialize(ClientInfo)}, caches it until shortly before it expires, attaches it and
 * sends the request. Thread-safe; one instance can serve many threads.
 *
 * <pre>{@code
 * try (OAuthServiceClient service = new OAuthServiceClient()) {
 *     service.initialize(clientInfo);
 *     ServiceResponse created = service.post("https://api.example.com/v1/items", json);
 *     ServiceResponse item = service.get("https://api.example.com/v1/items/42");
 *     ServiceResponse custom = service.request(ServiceRequest.put(url, json)
 *             .header("Accept", "application/json")
 *             .scopes("items.write"));
 * }
 * }</pre>
 *
 * <p>Every HTTP answer goes back to the caller as a {@link ServiceResponse}, whatever its status; only
 * failures without an answer (getting the token, connection, TLS, timeout, a response over the size limit)
 * throw {@link OAuthServiceException}. Redirects aren't followed: a 3xx comes back as is, so the token never
 * goes to another host.
 *
 * <p>When the service answers 401 to the library's token, the token is renewed once and the call sent once
 * more. A call is also resent when nothing was sent (the connection couldn't be made), or when the service
 * answers 429 or 503 with Retry-After, after that pause (at most 30 seconds); {@link
 * ServiceRequest#retryOnFailure()} adds 5xx and other failures for idempotent calls. Timeouts and the
 * number of retries come from the {@link #builder() builder}.
 *
 * <p>Tokens are cached for the whole JVM (per class loader) by service, tenant and scopes, so they outlive
 * {@link #close()}, and instances with the same client info share them. A caller with its own token passes
 * it ({@code post(token, url, json)}); the library then uses it as is, needs no client info, and never
 * renews it.
 */
public final class OAuthServiceClient implements AutoCloseable {

    /** Largest response body accepted from a service by default, in bytes. */
    static final int MAX_RESPONSE_BYTES = 16 * 1024 * 1024;
    static final Duration CONNECT_TIMEOUT = TokenClient.CONNECT_TIMEOUT;
    static final Duration READ_TIMEOUT = TokenClient.READ_TIMEOUT;
    static final Duration CALL_TIMEOUT = TokenClient.CALL_TIMEOUT;
    static final int RETRIES = 2;
    static final int MAX_RETRIES = 10;
    static final int MIN_RESPONSE_BYTES = 1024;
    static final int MAX_RESPONSE_BYTES_LIMIT = 256 * 1024 * 1024;

    /** The JVM-wide token cache, and the token client and executor for default settings, made on first use. */
    private static final class Shared {
        static final TokenCache CACHE = new TokenCache();
        static final Components DEFAULTS = new Components(CONNECT_TIMEOUT, READ_TIMEOUT, CALL_TIMEOUT, RETRIES);
    }

    /** One transport, with the token client and the service executor on it. */
    private static final class Components {
        final TokenFetcher fetcher;
        final HttpExecutor http;

        Components(Duration connect, Duration read, Duration call, int retries) {
            // no limit of the transport's own: every attempt gets what is left of its call's deadline
            UrlConnectionTransport transport = new UrlConnectionTransport(connect, read, null, null);
            // token requests keep their own retries, because vendors cap token requests
            this.fetcher = new TokenClient(new HttpExecutor(transport, TokenClient.MAX_RETRIES, TokenClient.RETRY_BACKOFF,
                    HttpExecutor.THREAD_SLEEPER, call), Clock.systemUTC());
            this.http = new HttpExecutor(transport, retries, TokenClient.RETRY_BACKOFF, HttpExecutor.THREAD_SLEEPER, call);
        }
    }

    private final TokenCache cache;
    private final TokenFetcher fetcher;
    private final HttpExecutor http;
    private final int maxResponseBytes;
    private volatile ClientInfo clientInfo;
    private volatile boolean closed;

    /**
     * A client with the default settings: the JVM's trust store, the shared token cache, 10 seconds to
     * connect, 30 seconds per read, 60 seconds per call, 2 retries and responses up to 16 MB. The same as
     * {@code builder().build()}. Call {@link #initialize(ClientInfo)} before calls that use the library's token.
     */
    public OAuthServiceClient() {
        this(Shared.CACHE, Shared.DEFAULTS.fetcher, Shared.DEFAULTS.http, MAX_RESPONSE_BYTES);
    }

    /** Settings for a client; {@link Builder#build()} checks them all at once. */
    public static Builder builder() {
        return new Builder();
    }

    OAuthServiceClient(TokenCache cache, TokenFetcher fetcher, HttpExecutor http, int maxResponseBytes) {
        this.cache = cache;
        this.fetcher = fetcher;
        this.http = http;
        this.maxResponseBytes = maxResponseBytes;
    }

    /**
     * Sets the client info this instance gets tokens with. May be called again, for example with a
     * rotated secret: a cached token stays in use as long as the settings that shape it are unchanged.
     *
     * @throws IllegalStateException if this client is closed
     */
    public void initialize(ClientInfo clientInfo) {
        checkOpen();
        this.clientInfo = Objects.requireNonNull(clientInfo, "clientInfo");
    }

    /** GET with the library's token. */
    public ServiceResponse get(String url) {
        return request(ServiceRequest.get(url));
    }

    /** GET with the caller's own token. */
    public ServiceResponse get(String token, String url) {
        return request(ServiceRequest.get(url).token(token));
    }

    /** POST of {@code payload} (JSON; {@code null} for no body) with the library's token. */
    public ServiceResponse post(String url, String payload) {
        return request(ServiceRequest.post(url, payload));
    }

    /** POST of {@code payload} (JSON; {@code null} for no body) with the caller's own token. */
    public ServiceResponse post(String token, String url, String payload) {
        return request(ServiceRequest.post(url, payload).token(token));
    }

    /** PUT of {@code payload} (JSON; {@code null} for no body) with the library's token. */
    public ServiceResponse put(String url, String payload) {
        return request(ServiceRequest.put(url, payload));
    }

    /** PUT of {@code payload} (JSON; {@code null} for no body) with the caller's own token. */
    public ServiceResponse put(String token, String url, String payload) {
        return request(ServiceRequest.put(url, payload).token(token));
    }

    /** DELETE with the library's token. */
    public ServiceResponse delete(String url) {
        return request(ServiceRequest.delete(url));
    }

    /** DELETE with the caller's own token. */
    public ServiceResponse delete(String token, String url) {
        return request(ServiceRequest.delete(url).token(token));
    }

    /**
     * Sends {@code request} with its own token, or else the library's token for the request's scopes (the
     * client info's when it sets none), and returns the answer, whatever its status.
     *
     * @throws OAuthServiceException when there's no answer: no token could be had, or the connection, TLS
     *         handshake or timeout failed, or the response was over 16 MB
     * @throws IllegalStateException if the request needs the library's token and {@link #initialize(ClientInfo)}
     *         wasn't called, or this client is closed
     */
    public ServiceResponse request(ServiceRequest request) {
        checkOpen();
        Objects.requireNonNull(request, "request");
        ClientInfo info = clientInfo;
        HttpExecutor.Retry retry = request.isRetryOnFailure() ? HttpExecutor.Retry.ALWAYS : HttpExecutor.Retry.BUSY_OR_NOT_SENT;
        if (request.hasOwnToken()) {
            // the caller's token is used as is: a 401 goes back to the caller
            return new ServiceResponse(send(request, "Bearer " + request.ownToken(), info, retry, deadline(request)));
        }
        AccessToken token = cache.get(requireInfo(info), request.getScopes(), fetcher);
        // one deadline for the whole call, the resend after a 401 included
        long deadline = deadline(request);
        HttpResponse response = send(request, token.toAuthorizationHeader(), info, retry, deadline);
        if (response.getStatus() == 401) {
            // the service turned the token away, so it didn't carry out the request: renew once, send once more
            AccessToken renewed = cache.renew(info, request.getScopes(), token, fetcher);
            if (deadline == 0 || deadline - System.nanoTime() > 0) {
                response = send(request, renewed.toAuthorizationHeader(), info, retry, deadline);
            }
        }
        return new ServiceResponse(response);
    }

    /** When this call must end, in {@link System#nanoTime()} terms: its own timeout, else the client's. */
    private long deadline(ServiceRequest request) {
        return request.getTimeout() != null ? System.nanoTime() + request.getTimeout().toNanos() : http.deadlineFromNow();
    }

    private HttpResponse send(ServiceRequest request, String authorization, ClientInfo info, HttpExecutor.Retry retry,
                              long deadline) {
        Map<String, String> headers = new LinkedHashMap<String, String>(request.headersToSend());
        headers.put("Authorization", authorization);
        byte[] body = request.getBody();
        boolean post = "POST".equals(request.getMethod());
        if (body == null && (post || "PUT".equals(request.getMethod()))) {
            // an empty body sends Content-Length: 0, which some servers require; a POST's is sent
            // fixed-length below, so the JDK can't resend it either
            body = new byte[0];
        }
        HttpRequest built = new HttpRequest(request.getMethod(), request.getUrl(), headers, body)
                .withMaxResponseBytes(maxResponseBytes)
                // certificate-bound tokens (RFC 8705) need the client certificate on the API call too
                .withClientCertificate(info == null ? null : info.getClientCertificate());
        // a POST may not be idempotent: the JDK must not quietly send it again on a stale connection
        final HttpRequest toSend = post ? built.notResendable() : built;
        return http.execute(new Supplier<HttpRequest>() {
            @Override
            public HttpRequest get() {
                return toSend;
            }
        }, retry, deadline);
    }

    /**
     * The library's token for the client info, from the cache or new; for fields of the token response the
     * caller needs, such as Salesforce's {@code instance_url}.
     *
     * @param scopes scopes replacing the client info's defaults; none for the defaults
     * @throws OAuthServiceException if no token could be had
     * @throws IllegalStateException if {@link #initialize(ClientInfo)} wasn't called, or this client is closed
     * @throws IllegalArgumentException if a scope is blank or has spaces
     */
    public AccessToken token(String... scopes) {
        checkOpen();
        return cache.get(requireInfo(clientInfo), Arrays.asList(scopes), fetcher);
    }

    /**
     * Ends this instance: later calls throw {@link IllegalStateException}. Cached tokens stay for other
     * instances. Calling it again does nothing.
     */
    @Override
    public void close() {
        closed = true;
    }

    private void checkOpen() {
        if (closed) {
            throw new IllegalStateException("This OAuthServiceClient is closed");
        }
    }

    /**
     * Settings for an {@link OAuthServiceClient}. Every instance shares the JVM-wide token cache; the
     * timeouts also apply to the instance's token requests, which keep their own 2 retries.
     */
    public static final class Builder {

        private Duration connectTimeout = CONNECT_TIMEOUT;
        private Duration readTimeout = READ_TIMEOUT;
        private Duration callTimeout = CALL_TIMEOUT;
        private int retries = RETRIES;
        private int maxResponseBytes = MAX_RESPONSE_BYTES;

        private Builder() {
        }

        /** Longest wait for the TCP connection and TLS handshake to a host; default 10 seconds. */
        public Builder connectTimeout(Duration v) {
            connectTimeout = v;
            return this;
        }

        /** Longest wait for each read from the server; default 30 seconds. */
        public Builder readTimeout(Duration v) {
            readTimeout = v;
            return this;
        }

        /**
         * Longest one call may take: its attempts, the pauses between them and the resend after a 401;
         * default 60 seconds. {@link ServiceRequest#timeout(Duration)} sets it for one call.
         */
        public Builder callTimeout(Duration v) {
            callTimeout = v;
            return this;
        }

        /** Most resends of one call (see {@link ServiceRequest#retryOnFailure()} for when); 0 to 10, default 2. */
        public Builder retries(int v) {
            retries = v;
            return this;
        }

        /** Largest response body accepted, in bytes; 1 KB to 256 MB, default 16 MB. */
        public Builder maxResponseBytes(int v) {
            maxResponseBytes = v;
            return this;
        }

        /** @throws IllegalArgumentException listing every setting that's out of range */
        public OAuthServiceClient build() {
            List<String> problems = new ArrayList<String>();
            checkPositive("connectTimeout", connectTimeout, problems);
            checkPositive("readTimeout", readTimeout, problems);
            checkPositive("callTimeout", callTimeout, problems);
            if (retries < 0 || retries > MAX_RETRIES) {
                problems.add("retries must be 0 to " + MAX_RETRIES);
            }
            if (maxResponseBytes < MIN_RESPONSE_BYTES || maxResponseBytes > MAX_RESPONSE_BYTES_LIMIT) {
                problems.add("maxResponseBytes must be 1 KB to 256 MB");
            }
            if (!problems.isEmpty()) {
                throw new IllegalArgumentException("Invalid OAuthServiceClient settings: " + String.join("; ", problems));
            }
            if (connectTimeout.equals(CONNECT_TIMEOUT) && readTimeout.equals(READ_TIMEOUT)
                    && callTimeout.equals(CALL_TIMEOUT) && retries == RETRIES) {
                return new OAuthServiceClient(Shared.CACHE, Shared.DEFAULTS.fetcher, Shared.DEFAULTS.http, maxResponseBytes);
            }
            Components components = new Components(connectTimeout, readTimeout, callTimeout, retries);
            return new OAuthServiceClient(Shared.CACHE, components.fetcher, components.http, maxResponseBytes);
        }

        private static void checkPositive(String name, Duration d, List<String> problems) {
            if (d == null || d.isNegative() || d.isZero()) {
                problems.add(name + " must be positive");
            }
        }
    }

    private static ClientInfo requireInfo(ClientInfo info) {
        if (info == null) {
            throw new IllegalStateException("Call initialize(clientInfo) first, or pass your own token");
        }
        return info;
    }
}
