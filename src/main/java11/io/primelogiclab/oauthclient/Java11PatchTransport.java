package io.primelogiclab.oauthclient;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.ConnectException;
import java.net.Proxy;
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
import java.util.concurrent.ExecutorService;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.Flow;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLParameters;
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

    /**
     * The JDK clients' worker threads: the library's daemon threads (its own class loader, no inherited thread
     * locals), so a client never keeps a web application loaded.
     */
    private static final ExecutorService THREADS = new ThreadPoolExecutor(0, Integer.MAX_VALUE, 30, TimeUnit.SECONDS,
            new SynchronousQueue<Runnable>(), r -> UrlConnectionTransport.daemon(r, "oauth-service-client-http-patch"));

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
        SSLContext tls = Tls.context(certificate, trustManagers);
        // host name checks set here, so the JVM-wide jdk.internal.httpclient.disableHostnameVerification
        // can't turn them off: java.net.http keeps a set identification algorithm
        SSLParameters params = tls.getDefaultSSLParameters();
        params.setEndpointIdentificationAlgorithm("HTTPS");
        HttpClient.Builder b = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .followRedirects(HttpClient.Redirect.NEVER)
                .sslContext(tls)
                .sslParameters(params)
                .executor(THREADS);
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
        // built on one of the library's threads: the client's selector thread inherits from the thread that
        // builds it (its class loader, its thread locals), and must not inherit the caller's
        try {
            return THREADS.submit(b::build).get();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new OAuthServiceException("Interrupted while setting up the PATCH client", e);
        } catch (ExecutionException e) {
            Throwable cause = e.getCause();
            throw cause instanceof RuntimeException ? (RuntimeException) cause
                    : new OAuthServiceException("Cannot set up the PATCH client: " + cause, cause);
        }
    }

    /**
     * Refuses a PATCH that would break the library's rules because of a JVM-wide setting: a resend
     * (jdk.httpclient.enableAllMethodRetry), or a direct connection that skips a SOCKS proxy, which
     * java.net.http can't use.
     */
    private static void checkJvmSettings(URI uri) {
        if (Boolean.parseBoolean(System.getProperty("jdk.httpclient.enableAllMethodRetry"))) {
            throw new OAuthServiceException("PATCH refused: the JVM-wide property jdk.httpclient.enableAllMethodRetry=true "
                    + "would let Java resend it");
        }
        ProxySelector proxies = ProxySelector.getDefault();
        if (proxies != null) {
            for (Proxy p : proxies.select(uri)) {
                if (p.type() == Proxy.Type.SOCKS) {
                    throw new OAuthServiceException("PATCH refused: a SOCKS proxy is configured, which java.net.http "
                            + "can't use, so it would connect directly");
                }
            }
        }
    }

    @Override
    public HttpResponse execute(HttpRequest request) throws IOException {
        long limitMs = requestTimeoutMs;
        if (request.getTimeout() != null) { // what is left of the caller's overall deadline
            long left = Math.max(1, request.getTimeout().toMillis());
            limitMs = limitMs <= 0 ? left : Math.min(limitMs, left);
        }
        URI uri = URI.create(request.getUrl());
        checkJvmSettings(uri);
        int maxBytes = request.getMaxResponseBytes() > 0
                ? request.getMaxResponseBytes() : UrlConnectionTransport.DEFAULT_MAX_RESPONSE_BYTES;
        long deadline = limitMs > 0 ? System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(limitMs) : 0;
        String host = UrlConnectionTransport.hostKey(request.getUrl());
        if (limitMs > 0) {
            UrlConnectionTransport.acquire(host, deadline, limitMs);
        }
        try {
            java.net.http.HttpRequest.Builder rb;
            try {
                byte[] body = request.getBody();
                rb = java.net.http.HttpRequest.newBuilder(uri)
                        .method(request.getMethod(), body == null
                                ? java.net.http.HttpRequest.BodyPublishers.noBody()
                                : java.net.http.HttpRequest.BodyPublishers.ofByteArray(body));
                for (Map.Entry<String, String> h : request.getHeaders().entrySet()) {
                    rb.header(h.getKey(), h.getValue());
                }
            } catch (IllegalArgumentException e) {
                // the JDK's message may quote a header value, which may be a credential: leave it out; not
                // "not sent" for the retries, since it would fail the same way again
                throw new IOException("The request can't be sent with java.net.http (a header it doesn't allow?)");
            }
            if (deadline != 0) { // only what is left after waiting for a slot
                rb.timeout(Duration.ofNanos(Math.max(1, deadline - System.nanoTime())));
            }
            final AtomicReference<LimitedBody> reading = new AtomicReference<LimitedBody>();
            CompletableFuture<java.net.http.HttpResponse<byte[]>> answer = clientFor(request.getClientCertificate())
                    .sendAsync(rb.build(), info -> {
                        LimitedBody b = new LimitedBody(maxBytes);
                        reading.set(b);
                        return b;
                    });
            java.net.http.HttpResponse<byte[]> r;
            try {
                r = deadline == 0 ? answer.get() : answer.get(Math.max(0, deadline - System.nanoTime()), TimeUnit.NANOSECONDS);
            } catch (TimeoutException e) {
                abort(answer, reading.get());
                throw new SocketTimeoutException("Request took longer than " + limitMs + " ms");
            } catch (InterruptedException e) {
                abort(answer, reading.get());
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

    /**
     * Ends the exchange: cancelling the body subscription closes the connection on every Java 11+ version
     * (cancelling the future does only from Java 16), so a server trickling its body can't keep it open.
     */
    private static void abort(CompletableFuture<?> answer, LimitedBody body) {
        if (body != null) {
            body.abort();
        }
        answer.cancel(true);
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
        private volatile Flow.Subscription subscription;

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

        /** Stops reading and closes the exchange. */
        void abort() {
            Flow.Subscription s = subscription;
            if (s != null) {
                s.cancel();
            }
            result.completeExceptionally(new IOException("Request abandoned at its deadline"));
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
