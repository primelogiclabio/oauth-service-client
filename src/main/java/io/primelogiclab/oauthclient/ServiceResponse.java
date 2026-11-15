package io.primelogiclab.oauthclient;

import java.util.List;
import java.util.Map;

/**
 * A service's answer, whatever its status: the library returns 4xx and 5xx answers too, for the caller to
 * handle. The body is kept as bytes, so a binary answer (a PDF) arrives intact; {@link #getBody()} gives
 * it as text. Immutable and thread-safe.
 */
public final class ServiceResponse {

    private final HttpResponse response;

    ServiceResponse(HttpResponse response) {
        this.response = response;
    }

    /**
     * The HTTP status.
     *
     * @return the status code, e.g. 200 or 404
     */
    public int getStatus() {
        return response.getStatus();
    }

    /**
     * Whether the service accepted the request.
     *
     * @return true for a 2xx status
     */
    public boolean isSuccessful() {
        return response.isSuccessful();
    }

    /**
     * The answer's headers.
     *
     * @return every header with its values in the order received; names are looked up case-insensitively.
     *         Unmodifiable
     */
    public Map<String, List<String>> getHeaders() {
        return response.getHeaders();
    }

    /**
     * One header's first value.
     *
     * @param name the header's name, in any case
     * @return its first value, or {@code null} when the answer doesn't have it
     */
    public String getHeader(String name) {
        return response.header(name);
    }

    /**
     * The body as text.
     *
     * @return the body decoded with the charset the {@code Content-Type} names (UTF-8 when it names none);
     *         empty when there is no body
     */
    public String getBody() {
        return response.getBody();
    }

    /**
     * The body as bytes, e.g. for a PDF.
     *
     * @return a copy of the body's bytes; empty when there is no body
     */
    public byte[] getBodyBytes() {
        return response.getBodyBytes();
    }

    /** Status, content type and body length; never the body, which may hold personal data. */
    @Override
    public String toString() {
        String type = response.header("Content-Type");
        return "ServiceResponse{status=" + response.getStatus()
                + (type == null ? "" : ", contentType=" + Strings.safe(type))
                + ", bodyLength=" + response.bodyLength() + '}';
    }
}
