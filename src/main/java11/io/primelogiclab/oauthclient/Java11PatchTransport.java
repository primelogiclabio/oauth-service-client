package io.primelogiclab.oauthclient;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.ConnectException;
import java.net.ProxySelector;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.net.UnknownHostException;
import java.net.http.HttpClient;
import java.net.http.HttpConnectTimeoutException;
import java.net.http.HttpTimeoutException;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Flow;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.TrustManager;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;

/**
 * Sends PATCH, which {@link java.net.HttpURLConnection} refuses, through Java 11's {@code java.net.http}
 * client, under the same rules as {@link UrlConnectionTransport}: the library's own TLS context (the JVM's
 * trust store or the given CAs, host names checked, a client certificate only when the request has one),
 * no redirects, never the JVM's Authenticator, the request's deadline and response size limit, and the
 * per-host limit. The JDK client doesn't resend a PATCH by itself. A proxy that asks for a login isn't
 * supported for PATCH.
 *
 * <p>Compiled with release 11 and loaded by name only on a Java 11+ runtime (see
 * {@link UrlConnectionTransport}), so the library still runs on Java 8.
 */
final class Java11PatchTransport implements HttpTransport {

    /** Most client certificates whose JDK client is kept; each client has a selector thread of its own. */
    static final long MAX_CERTIFICATE_CLIENTS = 50;

    private final Duration connectTimeout; // null = the JDK's default
    private final long requestTimeoutMs;   // 0 = none of its own
    private final TrustManager[] trustManagers;
    private final HttpClient plain;
    private final Cache<ClientKey, HttpClient> withCertificate =
            Caffeine.newBuilder().weakKeys().maximumSize(MAX_CERTIFICATE_CLIENTS).build();

    Java11PatchTransport(long connectTimeoutMs, long requestTimeoutMs, TrustManager[] trustManagers) {
        this.connectTimeout = connectTimeoutMs > 0 ? Duration.ofMillis(connectTimeoutMs) : null;
        this.requestTimeoutMs = requestTimeoutMs;
        this.trustManagers = trustManagers == null ? null : trustManagers.clone();
        this.plain = newClient(null);
    }

    /** The JDK client presenting {@code certificate}, or none; made once per key. */
    HttpClient clientFor(ClientKey certificate) {
        return certificate == null ? plain : withCertificate.get(certificate, this::newClient);
    }

    private HttpClient newClient(ClientKey certificate) {
        HttpClient.Builder b = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .followRedirects(HttpClient.Redirect.NEVER)
                .sslContext(Tls.context(certificate, trustManagers));
        // no authenticator: java.net.http then returns a 401 as an answer and never asks the JVM's default
        // Authenticator (with one set, a 401 becomes an IOException). So a proxy that asks for a login
        // isn't supported for PATCH.
        ProxySelector proxies = ProxySelector.getDefault();
        if (proxies != null) {
            b.proxy(proxies);
        }
        if (connectTimeout != null) {
            b.connectTimeout(connectTimeout);
        }
        return b.build();
    }

    @Override
    public HttpResponse execute(HttpRequest request) throws IOException {
        long limitMs = requestTimeoutMs;
        if (request.getTimeout() != null) { // what is left of the caller's overall deadline
            long left = Math.max(1, request.getTimeout().toMillis());
            limitMs = limitMs <= 0 ? left : Math.min(limitMs, left);
        }
        java.net.http.HttpRequest.Builder rb;
        try {
            byte[] body = request.getBody();
            rb = java.net.http.HttpRequest.newBuilder(URI.create(request.getUrl()))
                    .method(request.getMethod(), body == null
                            ? java.net.http.HttpRequest.BodyPublishers.noBody()
                            : java.net.http.HttpRequest.BodyPublishers.ofByteArray(body));
            for (Map.Entry<String, String> h : request.getHeaders().entrySet()) {
                rb.header(h.getKey(), h.getValue());
            }
        } catch (IllegalArgumentException e) {
            // the JDK's message may quote a header value, which may be a credential: leave it out
            throw new RequestNotSentException("The request can't be sent with java.net.http (a header it doesn't allow?)", null);
        }
        if (limitMs > 0) {
            rb.timeout(Duration.ofMillis(limitMs));
        }
        int maxBytes = request.getMaxResponseBytes() > 0
                ? request.getMaxResponseBytes() : UrlConnectionTransport.DEFAULT_MAX_RESPONSE_BYTES;
        long deadline = limitMs > 0 ? System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(limitMs) : 0;
        String host = UrlConnectionTransport.hostKey(request.getUrl());
        if (limitMs > 0) {
            UrlConnectionTransport.acquire(host, deadline, limitMs);
        }
        try {
            CompletableFuture<java.net.http.HttpResponse<byte[]>> answer = clientFor(request.getClientCertificate())
                    .sendAsync(rb.build(), info -> new LimitedBody(maxBytes));
            java.net.http.HttpResponse<byte[]> r;
            try {
                r = deadline == 0 ? answer.get() : answer.get(Math.max(0, deadline - System.nanoTime()), TimeUnit.NANOSECONDS);
            } catch (TimeoutException e) {
                answer.cancel(true); // ends the exchange and closes its connection
                throw new SocketTimeoutException("Request took longer than " + limitMs + " ms");
            } catch (InterruptedException e) {
                answer.cancel(true);
                Thread.currentThread().interrupt();
                throw new InterruptedIOException("Interrupted while waiting for the response");
            } catch (ExecutionException e) {
                throw failure(e.getCause(), host);
            }
            return new HttpResponse(r.statusCode(), r.headers().map(), r.body());
        } finally {
            if (limitMs > 0) {
                UrlConnectionTransport.release(host);
            }
        }
    }

    /** The JDK client's failure as the library's transport failures: "not sent" when no connection was made. */
    private static IOException failure(Throwable cause, String host) {
        if (cause instanceof HttpConnectTimeoutException || cause instanceof ConnectException
                || cause instanceof UnknownHostException || cause instanceof SSLHandshakeException) {
            return new RequestNotSentException("Could not connect to " + host + ": " + cause, cause);
        }
        if (cause instanceof HttpTimeoutException) {
            SocketTimeoutException timeout = new SocketTimeoutException("Request timed out");
            timeout.initCause(cause);
            return timeout;
        }
        if (cause instanceof IOException) {
            return (IOException) cause;
        }
        return new IOException(String.valueOf(cause), cause);
    }

    /** Collects the body, and gives up (closing the exchange) once it passes {@code limit} bytes. */
    private static final class LimitedBody implements java.net.http.HttpResponse.BodySubscriber<byte[]> {

        private final int limit;
        private final ByteArrayOutputStream buf = new ByteArrayOutputStream();
        private final CompletableFuture<byte[]> result = new CompletableFuture<byte[]>();
        private Flow.Subscription subscription;

        LimitedBody(int limit) {
            this.limit = limit;
        }

        @Override
        public CompletionStage<byte[]> getBody() {
            return result;
        }

        @Override
        public void onSubscribe(Flow.Subscription s) {
            subscription = s;
            s.request(Long.MAX_VALUE);
        }

        @Override
        public void onNext(List<ByteBuffer> items) {
            if (result.isDone()) {
                return;
            }
            for (ByteBuffer b : items) {
                int n = b.remaining();
                if (buf.size() + n > limit) {
                    subscription.cancel();
                    result.completeExceptionally(new IOException("Response body exceeds " + limit + " bytes"));
                    return;
                }
                byte[] chunk = new byte[n];
                b.get(chunk);
                buf.write(chunk, 0, n);
            }
        }

        @Override
        public void onError(Throwable t) {
            result.completeExceptionally(t);
        }

        @Override
        public void onComplete() {
            result.complete(buf.toByteArray());
        }
    }
}
