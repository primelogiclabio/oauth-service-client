package io.primelogiclab.oauthclient;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Immutable HTTP response. Header lookups are case-insensitive. The body is kept as bytes, so a binary
 * answer (a PDF) arrives intact; {@link #getBody()} decodes it as text.
 */
final class HttpResponse {

    private final int status;
    private final Map<String, List<String>> headers;
    private final byte[] body;

    HttpResponse(int status, Map<String, List<String>> headers, byte[] body) {
        this.status = status;
        Map<String, List<String>> copy = new TreeMap<String, List<String>>(String.CASE_INSENSITIVE_ORDER);
        if (headers != null) {
            for (Map.Entry<String, List<String>> e : headers.entrySet()) {
                if (e.getKey() != null && e.getValue() != null) {
                    copy.put(e.getKey(), Collections.unmodifiableList(new ArrayList<String>(e.getValue())));
                }
            }
        }
        this.headers = Collections.unmodifiableMap(copy);
        this.body = body == null ? new byte[0] : body.clone();
    }

    /** A response with a UTF-8 text body; for tests and stub transports. */
    HttpResponse(int status, Map<String, List<String>> headers, String body) {
        this(status, headers, body == null ? null : body.getBytes(StandardCharsets.UTF_8));
    }

    int getStatus() {
        return status;
    }

    Map<String, List<String>> getHeaders() {
        return headers;
    }

    /** First value of the given header, or {@code null}. */
    String header(String name) {
        List<String> values = headers.get(name);
        return values == null || values.isEmpty() ? null : values.get(0);
    }

    /** The body as text, decoded with the Content-Type charset (UTF-8 when it names none or an unknown one). */
    String getBody() {
        return new String(body, charsetOf(header("Content-Type")));
    }

    /** A copy of the body's bytes; empty when there was none. */
    byte[] getBodyBytes() {
        return body.clone();
    }

    /** Length of the body in bytes. */
    int bodyLength() {
        return body.length;
    }

    boolean isSuccessful() {
        return status >= 200 && status < 300;
    }

    static Charset charsetOf(String contentType) {
        if (contentType != null) {
            for (String part : contentType.split(";")) {
                String p = part.trim();
                if (p.regionMatches(true, 0, "charset=", 0, 8)) {
                    try {
                        return Charset.forName(p.substring(8).replace("\"", "").trim());
                    } catch (RuntimeException ignored) {
                        // fall through to UTF-8
                    }
                }
            }
        }
        return StandardCharsets.UTF_8;
    }
}
