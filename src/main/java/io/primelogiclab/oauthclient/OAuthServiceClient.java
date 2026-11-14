package io.primelogiclab.oauthclient;

import java.time.Duration;
import java.util.Arrays;
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
 * failures without an answer (getting the token, connection, TLS, timeout, a response over 16 MB) throw
 * {@link OAuthServiceException}. Redirects aren't followed: a 3xx comes back as is, so the token never
 * goes to another host. A POST is sent at most once.
 *
 * <p>Tokens are cached for the whole JVM (per class loader) by service, tenant and scopes, so they outlive
 * {@link #close()}, and instances with the same client info share them. A caller with its own token passes
 * it ({@code post(token, url, json)}); the library then uses it as is, needs no client info, and never
 * renews it.
 */
public final class OAuthServiceClient implements AutoCloseable {

    /** Largest response body accepted from a service, in bytes. */
    static final int MAX_RESPONSE_BYTES = 16 * 1024 * 1024;

    /** The JVM-wide token cache, token client and HTTP executor, made on first use. */
    private static final class Shared {
        static final TokenCache CACHE = new TokenCache();
        static final TokenFetcher FETCHER = TokenClient.withDefaults();
        static final HttpExecutor HTTP = new HttpExecutor(
                new UrlConnectionTransport(TokenClient.CONNECT_TIMEOUT, TokenClient.READ_TIMEOUT,
                        TokenClient.CALL_TIMEOUT, null),
                0, Duration.ZERO, HttpExecutor.THREAD_SLEEPER, TokenClient.CALL_TIMEOUT);
    }

    private final TokenCache cache;
    private final TokenFetcher fetcher;
    private final HttpExecutor http;
    private final int maxResponseBytes;
    private volatile ClientInfo clientInfo;
    private volatile boolean closed;

    /**
     * A client with the JVM's trust store, the shared token cache, 10 seconds to connect, 30 seconds per
     * read and 60 seconds per call. Call {@link #initialize(ClientInfo)} before calls that use the library's token.
     */
    public OAuthServiceClient() {
        this(Shared.CACHE, Shared.FETCHER, Shared.HTTP, MAX_RESPONSE_BYTES);
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
        String authorization;
        if (request.hasOwnToken()) {
            authorization = "Bearer " + request.ownToken();
        } else {
            authorization = cache.get(requireInfo(info), request.getScopes(), fetcher).toAuthorizationHeader();
        }
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
        HttpResponse response = http.execute(new Supplier<HttpRequest>() {
            @Override
            public HttpRequest get() {
                return toSend;
            }
        }, HttpExecutor.Retry.NEVER);
        return new ServiceResponse(response);
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

    private static ClientInfo requireInfo(ClientInfo info) {
        if (info == null) {
            throw new IllegalStateException("Call initialize(clientInfo) first, or pass your own token");
        }
        return info;
    }
}
