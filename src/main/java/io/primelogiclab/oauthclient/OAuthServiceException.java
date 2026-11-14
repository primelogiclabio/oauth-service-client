package io.primelogiclab.oauthclient;

/**
 * A failure without a usable answer: the token couldn't be had, or the connection, TLS handshake or
 * timeout failed. When the token endpoint answered with an OAuth error (RFC 6749 section 5.2),
 * {@link #getError()} and {@link #getErrorDescription()} carry its values. Messages never contain
 * secrets or tokens.
 */
public class OAuthServiceException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    private final String error;
    private final String errorDescription;
    private final String errorUri;
    private final int httpStatus;

    public OAuthServiceException(String message) {
        this(message, null, null, null, -1, null);
    }

    public OAuthServiceException(String message, Throwable cause) {
        this(message, null, null, null, -1, cause);
    }

    public OAuthServiceException(String message, String error, String errorDescription, String errorUri,
                                 int httpStatus, Throwable cause) {
        super(message, cause);
        this.error = error;
        this.errorDescription = errorDescription;
        this.errorUri = errorUri;
        this.httpStatus = httpStatus;
    }

    /** The OAuth {@code error} code (e.g. {@code invalid_client}), or {@code null}. */
    public String getError() {
        return error;
    }

    /** The OAuth {@code error_description}, or {@code null}. */
    public String getErrorDescription() {
        return errorDescription;
    }

    /** The OAuth {@code error_uri}, or {@code null}. */
    public String getErrorUri() {
        return errorUri;
    }

    /** HTTP status of the failing answer, or -1 if there was none. */
    public int getHttpStatus() {
        return httpStatus;
    }
}
