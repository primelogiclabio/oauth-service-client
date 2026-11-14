package io.primelogiclab.oauthclient;

import java.io.IOException;

/**
 * Pluggable HTTP transport. The default is {@link UrlConnectionTransport}, which needs no
 * third-party libraries. Implement this to route calls through Apache HttpClient, OkHttp,
 * the Java 11+ {@code java.net.http.HttpClient}, a service mesh client, etc.
 *
 * <p>Implementations must be thread-safe and must return non-2xx responses rather than throw.
 * {@link IOException} is reserved for transport failures (connect, timeout, TLS). Throw
 * {@link RequestNotSentException} when the request certainly did not reach the server (the
 * connection or TLS handshake failed): only then is a refresh request retried.
 */
interface HttpTransport {

    HttpResponse execute(HttpRequest request) throws IOException;
}
