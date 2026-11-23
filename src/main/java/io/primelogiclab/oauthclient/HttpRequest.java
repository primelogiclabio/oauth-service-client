package io.primelogiclab.oauthclient;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Immutable outgoing HTTP request.
 */
final class HttpRequest {

    private final String method;
    private final String url;
    private final Map<String, String> headers;
    private final byte[] body;
    private final boolean resendable;
    private final Duration timeout;
    private final ClientKey clientCertificate;
    private final int maxResponseBytes;
    private final boolean ownConnection;

    HttpRequest(String method, String url, Map<String, String> headers, byte[] body) {
        this(method, url, headers, body, true, null, null, 0, false);
    }

    private HttpRequest(String method, String url, Map<String, String> headers, byte[] body, boolean resendable,
                        Duration timeout, ClientKey clientCertificate, int maxResponseBytes, boolean ownConnection) {
        this.method = method;
        this.url = url;
        this.headers = Collections.unmodifiableMap(new LinkedHashMap<String, String>(headers));
        this.body = body == null ? null : body.clone();
        this.resendable = resendable;
        this.timeout = timeout;
        this.clientCertificate = clientCertificate;
        this.maxResponseBytes = maxResponseBytes;
        this.ownConnection = ownConnection;
    }

    /**
     * This request marked as one that must reach the server at most once (a refresh with a rotating
     * refresh token). A transport must then never resend it on its own; for {@link java.net.HttpURLConnection}
     * that means fixed-length streaming mode, which turns off the JDK's automatic POST retry.
     */
    HttpRequest notResendable() {
        return new HttpRequest(method, url, headers, body, false, timeout, clientCertificate, maxResponseBytes,
                ownConnection);
    }

    /** This request presenting {@code certificate} in the TLS handshake (mutual TLS); {@code null} for none. */
    HttpRequest withClientCertificate(ClientKey certificate) {
        return new HttpRequest(method, url, headers, body, resendable, timeout, certificate, maxResponseBytes,
                ownConnection);
    }

    /**
     * This request accepting a response body of up to {@code bytes}; a larger one fails the request.
     * 0 means the transport's default.
     */
    HttpRequest withMaxResponseBytes(int bytes) {
        return new HttpRequest(method, url, headers, body, resendable, timeout, clientCertificate, bytes, ownConnection);
    }

    /**
     * This request on a connection of its own, opened for it and closed after it: never one kept alive from
     * another request, nor kept for a later one. Token requests use this: a kept-alive connection the server
     * closes at that moment would fail one after sending, and with vendor caps and rotating refresh tokens it
     * can't simply be sent again.
     */
    HttpRequest withOwnConnection() {
        return new HttpRequest(method, url, headers, body, resendable, timeout, clientCertificate, maxResponseBytes, true);
    }

    /** True when this request gets a connection of its own; see {@link #withOwnConnection()}. */
    boolean isOwnConnection() {
        return ownConnection;
    }

    /** Largest response body accepted, in bytes; 0 for the transport's default. */
    int getMaxResponseBytes() {
        return maxResponseBytes;
    }

    /** The client certificate for the TLS handshake, or {@code null}. */
    ClientKey getClientCertificate() {
        return clientCertificate;
    }

    /** False when the transport must not resend this request by itself; see {@link #notResendable()}. */
    public boolean isResendable() {
        return resendable;
    }

    /**
     * This request with the time left for it: when a call is retried, the later attempts get what
     * remains of the call's overall deadline. A transport should end the request (connect, send and
     * read) within the shorter of this and its own request timeout.
     */
    public HttpRequest withTimeout(Duration timeout) {
        return new HttpRequest(method, url, headers, body, resendable, timeout, clientCertificate, maxResponseBytes,
                ownConnection);
    }

    /** The time left for this request, or {@code null} to use the transport's own request timeout. */
    public Duration getTimeout() {
        return timeout;
    }

    public static HttpRequest get(String url, Map<String, String> headers) {
        return new HttpRequest("GET", url, headers, null);
    }

    public static HttpRequest post(String url, Map<String, String> headers, String body) {
        return new HttpRequest("POST", url, headers, body == null ? null : body.getBytes(StandardCharsets.UTF_8));
    }

    public String getMethod() {
        return method;
    }

    public String getUrl() {
        return url;
    }

    public Map<String, String> getHeaders() {
        return headers;
    }

    /** A copy of the body; {@code null} for requests without a body. */
    public byte[] getBody() {
        return body == null ? null : body.clone();
    }

    @Override
    public String toString() {
        // Never include headers or body: they carry credentials. The URL is redacted too.
        return method + " " + redactUrl(url);
    }

    /**
     * The URL without user info, query string or fragment, for messages and logs: some services put
     * keys there (for example an Azure Functions {@code ?code=}). A removed query shows as {@code ?...}.
     */
    public static String redactUrl(String url) {
        if (url == null) {
            return null;
        }
        // URLs can come from a server's metadata: no line breaks or other control characters in logs
        url = url.replaceAll("[\\p{Cc}\\p{Cf}\\u2028\\u2029]", "?");
        String rest = url;
        String prefix = "";
        int scheme = url.indexOf("://");
        if (scheme >= 0) {
            // User info first, before cutting at '?' or '#': an unencoded password may contain those,
            // or '/'. The last '@' before the query is taken as its end (over-redacting a rare '@' in a
            // path is harmless in a message).
            prefix = url.substring(0, scheme + 3);
            rest = url.substring(scheme + 3);
            int at = rest.lastIndexOf('@');
            if (at >= 0) {
                int slash = rest.indexOf('/');
                int q = firstOf(rest, 0);
                // an '@' after the '?' that ends the host (or the host and path) is query text (e.g.
                // ?mail=a@b), unless the part before it looks like user:password; otherwise all up to the
                // last '@' is user info
                int hostEnd = slash >= 0 && slash < q ? slash : q;
                boolean queryAt = q >= 0 && q < at && !looksLikeUserInfo(rest.substring(0, hostEnd));
                int cutAt = queryAt ? rest.lastIndexOf('@', q) : at; // user info, if any, ends before the query
                if (cutAt >= 0) {
                    // an '@' after the first '/' is ambiguous (unencoded password or path): mark the cut, so
                    // the message does not present what follows as the host
                    boolean ambiguous = slash >= 0 && cutAt > slash;
                    rest = (ambiguous ? "...@" : "") + rest.substring(cutAt + 1);
                }
            }
        }
        int cut = firstOf(rest, 0);
        return cut < 0 ? prefix + rest : prefix + rest.substring(0, cut) + "?...";
    }

    private static boolean looksLikeUserInfo(String authority) {
        int colon = authority.indexOf(':');
        return colon >= 0 && !authority.substring(colon + 1).matches("[0-9]*");
    }

    private static int firstOf(String s, int from) {
        int q = s.indexOf('?', from);
        int f = s.indexOf('#', from);
        return q < 0 ? f : f < 0 ? q : Math.min(q, f);
    }
}
