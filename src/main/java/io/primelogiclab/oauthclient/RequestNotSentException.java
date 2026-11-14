package io.primelogiclab.oauthclient;

import java.io.IOException;

/**
 * Thrown by an {@link HttpTransport} when a request failed before any of it reached the server,
 * for example because the connection or the TLS handshake failed. The library then knows it may
 * safely send the request again, even when the request is not idempotent (a refresh with a
 * rotating refresh token). {@link java.net.ConnectException} and
 * {@link java.net.UnknownHostException} are treated the same way.
 */
class RequestNotSentException extends IOException {

    private static final long serialVersionUID = 1L;

    public RequestNotSentException(String message, Throwable cause) {
        super(message, cause);
    }
}
