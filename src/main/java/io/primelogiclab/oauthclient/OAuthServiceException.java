package io.primelogiclab.oauthclient;

/**
 * A failure without a usable answer: the token couldn't be had, or the connection, TLS handshake or
 * timeout failed. When the token endpoint answered with an OAuth error (RFC 6749 section 5.2),
 * {@link #getError()} and {@link #getErrorDescription()} carry its values. Messages never contain
 * secrets or tokens.
 */
public class OAuthServiceException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    /** The OAuth {@code error} code, or {@code null}. */
    private final String error;
    /** The OAuth {@code error_description}, or {@code null}. */
    private final String errorDescription;
    /** The OAuth {@code error_uri}, or {@code null}. */
    private final String errorUri;
    /** The HTTP status of the failing answer, or -1 when there was none. */
    private final int httpStatus;

    /**
     * A failure with no OAuth error and no HTTP status, e.g. for a caller's own tests.
     *
     * @param message what failed; must not contain secrets or tokens
     */
    public OAuthServiceException(String message) {
        this(message, null, null, null, -1, null);
    }

    /**
     * A failure with no OAuth error and no HTTP status, caused by {@code cause}.
     *
     * @param message what failed; must not contain secrets or tokens
     * @param cause   the underlying failure, or {@code null}
     */
    public OAuthServiceException(String message, Throwable cause) {
        this(message, null, null, null, -1, cause);
    }

    /** Package-private: only the library knows the OAuth error and HTTP status of a failure. */
    OAuthServiceException(String message, String error, String errorDescription, String errorUri,
                          int httpStatus, Throwable cause) {
        super(message, cause);
        this.error = error;
        this.errorDescription = errorDescription;
        this.errorUri = errorUri;
        this.httpStatus = httpStatus;
    }

    /**
     * The OAuth error code.
     *
     * @return the {@code error} value, e.g. {@code invalid_client}, or {@code null} when there was none
     */
    public String getError() {
        return error;
    }

    /**
     * The OAuth error description.
     *
     * @return the {@code error_description} value, or {@code null} when there was none
     */
    public String getErrorDescription() {
        return errorDescription;
    }

    /**
     * The OAuth error URI.
     *
     * @return the {@code error_uri} value, or {@code null} when there was none
     */
    public String getErrorUri() {
        return errorUri;
    }

    /**
     * The HTTP status of the failing answer.
     *
     * @return the status, or -1 when there was no answer
     */
    public int getHttpStatus() {
        return httpStatus;
    }
}
