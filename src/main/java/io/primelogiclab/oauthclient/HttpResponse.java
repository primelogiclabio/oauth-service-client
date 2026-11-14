package io.primelogiclab.oauthclient;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Immutable HTTP response. Header lookups are case-insensitive.
 */
final class HttpResponse {

    private final int status;
    private final Map<String, List<String>> headers;
    private final String body;

    public HttpResponse(int status, Map<String, List<String>> headers, String body) {
        this.status = status;
        Map<String, List<String>> copy = new TreeMap<String, List<String>>(String.CASE_INSENSITIVE_ORDER);
        if (headers != null) {
            for (Map.Entry<String, List<String>> e : headers.entrySet()) {
                if (e.getKey() != null) {
                    copy.put(e.getKey(), e.getValue());
                }
            }
        }
        this.headers = Collections.unmodifiableMap(copy);
        this.body = body == null ? "" : body;
    }

    public int getStatus() {
        return status;
    }

    public Map<String, List<String>> getHeaders() {
        return headers;
    }

    /** First value of the given header, or {@code null}. */
    public String header(String name) {
        List<String> values = headers.get(name);
        return values == null || values.isEmpty() ? null : values.get(0);
    }

    public String getBody() {
        return body;
    }

    public boolean isSuccessful() {
        return status >= 200 && status < 300;
    }
}
