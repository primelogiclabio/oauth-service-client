package io.primelogiclab.oauthclient;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * One call to a service, for {@link OAuthServiceClient#request(ServiceRequest)}: method, https URL,
 * headers, body, and either the scopes for the library's token or the caller's own token. Immutable and
 * thread-safe: every method that changes something returns a new request.
 *
 * <pre>{@code
 * ServiceRequest put = ServiceRequest.put(url, json)
 *         .header("Accept", "application/json")
 *         .scopes("api");
 * }</pre>
 *
 * <p>A String body is sent as UTF-8, by default as {@code application/json; charset=UTF-8}; a byte body
 * as {@code application/octet-stream}; {@link #contentType(String)} overrides either. The
 * {@code Authorization} header is the library's (pass your own token with {@link #token(String)}), and
 * headers the JDK sets itself, such as {@code Host} and {@code Content-Length}, can't be set.
 */
public final class ServiceRequest {

    static final String DEFAULT_TEXT_TYPE = "application/json; charset=UTF-8";
    static final String DEFAULT_BYTES_TYPE = "application/octet-stream";

    private static final Set<String> METHODS = new HashSet<String>(
            Arrays.asList("GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS"));
    /** Methods sent without a body: HttpURLConnection turns a GET with a body into a POST, and Java 8 refuses DELETE with one. */
    private static final Set<String> NO_BODY = new HashSet<String>(Arrays.asList("GET", "HEAD", "DELETE", "OPTIONS"));
    /** Headers HttpURLConnection sets itself and quietly drops when a caller sets them (its restricted list). */
    private static final Set<String> JDK_HEADERS = new HashSet<String>(Arrays.asList(
            "access-control-request-headers", "access-control-request-method", "connection", "content-length",
            "content-transfer-encoding", "host", "keep-alive", "origin", "trailer", "transfer-encoding", "upgrade", "via"));

    private final String method;
    private final String url;
    private final Map<String, String> headers;
    private final byte[] body;
    private final boolean textBody;
    private final List<String> scopes;
    private final String token;
    private final boolean retryOnFailure;
    private final Duration timeout;

    private ServiceRequest(String method, String url, Map<String, String> headers, byte[] body, boolean textBody,
                           List<String> scopes, String token, boolean retryOnFailure, Duration timeout) {
        this.method = method;
        this.url = url;
        this.headers = headers;
        this.body = body;
        this.textBody = textBody;
        this.scopes = scopes;
        this.token = token;
        this.retryOnFailure = retryOnFailure;
        this.timeout = timeout;
    }

    /** A GET to {@code url}. */
    public static ServiceRequest get(String url) {
        return of("GET", url, null);
    }

    /** A HEAD to {@code url}. */
    public static ServiceRequest head(String url) {
        return of("HEAD", url, null);
    }

    /** A DELETE to {@code url}. */
    public static ServiceRequest delete(String url) {
        return of("DELETE", url, null);
    }

    /** A POST of {@code payload} (JSON by default; {@code null} for no body) to {@code url}. */
    public static ServiceRequest post(String url, String payload) {
        return of("POST", url, payload);
    }

    /** A PUT of {@code payload} (JSON by default; {@code null} for no body) to {@code url}. */
    public static ServiceRequest put(String url, String payload) {
        return of("PUT", url, payload);
    }

    /**
     * A request with any supported method: GET, HEAD, POST, PUT, DELETE or OPTIONS.
     *
     * @param payload the body (JSON by default), {@code null} for none; only POST and PUT take one
     * @throws IllegalArgumentException if the method isn't supported (PATCH isn't yet: {@link
     *         java.net.HttpURLConnection} can't send it), the URL isn't https, or a body-less method has a payload
     */
    public static ServiceRequest of(String method, String url, String payload) {
        String m = checkMethod(method);
        String problem = ClientInfo.urlProblem(url);
        if (problem != null) {
            // never the value: a token passed in the URL's place must not end up in a log
            throw new IllegalArgumentException("url " + problem);
        }
        ServiceRequest request = new ServiceRequest(m, url, emptyHeaders(), null, false,
                Collections.<String>emptyList(), null, false, null);
        return payload == null ? request : request.body(payload);
    }

    /**
     * This request with a header; one set before under the same name (in any case) is replaced.
     *
     * @throws IllegalArgumentException if the name isn't a valid header name, the value has a line break or
     *         other control character, or the header is {@code Authorization} or one the JDK sets itself
     */
    public ServiceRequest header(String name, String value) {
        if (name != null && "authorization".equalsIgnoreCase(name.trim())) {
            throw new IllegalArgumentException("The Authorization header is set by the library; pass your own token with token(...)");
        }
        String problem = HttpExecutor.headerProblem(Collections.singletonMap(name, value));
        if (problem != null) {
            throw new IllegalArgumentException(problem);
        }
        if (JDK_HEADERS.contains(name.toLowerCase(Locale.ROOT))) {
            throw new IllegalArgumentException("Header " + name + " is set by the JDK and can't be set here");
        }
        Map<String, String> h = copyHeaders();
        h.remove(name); // the name's case as last set
        h.put(name, value);
        return new ServiceRequest(method, url, Collections.unmodifiableMap(h), body, textBody, scopes, token, retryOnFailure, timeout);
    }

    /** This request with the body's {@code Content-Type}, e.g. {@code application/xml}. */
    public ServiceRequest contentType(String type) {
        return header("Content-Type", type);
    }

    /**
     * This request with a text body, sent as UTF-8; {@code application/json; charset=UTF-8} unless a
     * content type is set.
     *
     * @throws IllegalArgumentException if the method is sent without a body (GET, HEAD, DELETE, OPTIONS)
     */
    public ServiceRequest body(String text) {
        if (text == null) {
            throw new NullPointerException("body");
        }
        return withBody(text.getBytes(StandardCharsets.UTF_8), true);
    }

    /**
     * This request with a binary body; {@code application/octet-stream} unless a content type is set.
     *
     * @throws IllegalArgumentException if the method is sent without a body (GET, HEAD, DELETE, OPTIONS)
     */
    public ServiceRequest body(byte[] bytes) {
        if (bytes == null) {
            throw new NullPointerException("body");
        }
        return withBody(bytes.clone(), false);
    }

    /**
     * This request asking for a library token with these scopes, which replace the client info's
     * defaults for it; none for the defaults.
     *
     * @throws IllegalArgumentException if a scope is blank or has spaces, or the request carries the caller's own token
     */
    public ServiceRequest scopes(String... scopes) {
        if (token != null) {
            throw new IllegalArgumentException("Scopes apply to the library's token; this request carries your own token");
        }
        List<String> problems = new ArrayList<String>();
        List<String> checked = ClientInfo.checkScopes(Arrays.asList(scopes), problems);
        if (!problems.isEmpty()) {
            throw new IllegalArgumentException("Invalid scopes: " + String.join("; ", problems));
        }
        return new ServiceRequest(method, url, headers, body, textBody, checked, token, retryOnFailure, timeout);
    }

    /**
     * This request sent with the caller's own access token, as {@code Authorization: Bearer <token>}. The
     * library uses it as is: it isn't cached, and a 401 goes back to the caller.
     *
     * @throws IllegalArgumentException if the token is blank or has characters not allowed in an HTTP
     *         header, or scopes were set (they apply only to the library's token)
     */
    public ServiceRequest token(String token) {
        if (!scopes.isEmpty()) {
            throw new IllegalArgumentException("Scopes apply to the library's token, not your own; set one or the other");
        }
        if (Strings.isBlank(token)) {
            throw new IllegalArgumentException("token is blank");
        }
        String t = token.trim();
        for (int i = 0; i < t.length(); i++) {
            char c = t.charAt(i);
            if (c < 0x21 || c > 0x7e) {
                // never the value: it's a credential
                throw new IllegalArgumentException("token has characters not allowed in an HTTP header (spaces, line breaks or non-ASCII)");
            }
        }
        return new ServiceRequest(method, url, headers, body, textBody, scopes, t, retryOnFailure, timeout);
    }

    /**
     * This request also retried on a 5xx, on a 429 without Retry-After, and when the connection fails after
     * the request was sent; at most the client's {@code retries} times, within the call's timeout. Meant for
     * idempotent calls (GET, PUT, DELETE): a POST retried this way may be carried out twice.
     *
     * <p>Without it a call is resent only when nothing was sent (the connection couldn't be made) or the
     * service answered 429 or 503 with Retry-After, asking to come back.
     */
    public ServiceRequest retryOnFailure() {
        return new ServiceRequest(method, url, headers, body, textBody, scopes, token, true, timeout);
    }

    /**
     * This request with its own limit for the whole call (attempts, pauses and the resend after a 401),
     * instead of the client's call timeout; for a large download, say.
     *
     * @throws IllegalArgumentException if the timeout isn't positive
     */
    public ServiceRequest timeout(Duration timeout) {
        if (timeout == null || timeout.isNegative() || timeout.isZero()) {
            throw new IllegalArgumentException("timeout must be positive");
        }
        return new ServiceRequest(method, url, headers, body, textBody, scopes, token, retryOnFailure, timeout);
    }

    /** True when {@link #retryOnFailure()} was asked for. */
    public boolean isRetryOnFailure() {
        return retryOnFailure;
    }

    /** This call's own timeout, or {@code null} for the client's. */
    public Duration getTimeout() {
        return timeout;
    }

    public String getMethod() {
        return method;
    }

    public String getUrl() {
        return url;
    }

    /** The headers set on this request, without the defaults the library adds; unmodifiable, names case-insensitive. */
    public Map<String, String> getHeaders() {
        return headers;
    }

    /** A copy of the body; {@code null} when there's none. */
    public byte[] getBody() {
        return body == null ? null : body.clone();
    }

    /** The scopes for the library's token; empty for the client info's defaults. Unmodifiable. */
    public List<String> getScopes() {
        return scopes;
    }

    /** True when this request carries the caller's own token. */
    public boolean hasOwnToken() {
        return token != null;
    }

    /** The caller's own token, or {@code null}; package-private so it never shows up by accident. */
    String ownToken() {
        return token;
    }

    /** The headers to send, without Authorization: the caller's, plus the default content type when there's a body. */
    Map<String, String> headersToSend() {
        Map<String, String> h = copyHeaders();
        if (body != null && !h.containsKey("Content-Type")) {
            h.put("Content-Type", textBody ? DEFAULT_TEXT_TYPE : DEFAULT_BYTES_TYPE);
        }
        return h;
    }

    @Override
    public String toString() {
        // never headers, body or token: they may carry credentials; the URL without its query
        return method + " " + HttpRequest.redactUrl(url);
    }

    private ServiceRequest withBody(byte[] bytes, boolean text) {
        if (NO_BODY.contains(method)) {
            throw new IllegalArgumentException(method + " requests are sent without a body");
        }
        return new ServiceRequest(method, url, headers, bytes, text, scopes, token, retryOnFailure, timeout);
    }

    private Map<String, String> copyHeaders() {
        Map<String, String> h = new TreeMap<String, String>(String.CASE_INSENSITIVE_ORDER);
        h.putAll(headers);
        return h;
    }

    private static Map<String, String> emptyHeaders() {
        return Collections.unmodifiableMap(new TreeMap<String, String>(String.CASE_INSENSITIVE_ORDER));
    }

    private static String checkMethod(String method) {
        if (method == null) {
            throw new NullPointerException("method");
        }
        String m = method.trim().toUpperCase(Locale.ROOT);
        if ("PATCH".equals(m)) {
            throw new IllegalArgumentException("PATCH isn't supported yet: java.net.HttpURLConnection can't send it");
        }
        if (!METHODS.contains(m)) {
            throw new IllegalArgumentException("Method " + Strings.safe(method)
                    + " isn't supported; use GET, HEAD, POST, PUT, DELETE or OPTIONS");
        }
        return m;
    }
}
