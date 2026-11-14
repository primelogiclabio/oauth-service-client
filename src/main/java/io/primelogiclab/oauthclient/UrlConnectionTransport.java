package io.primelogiclab.oauthclient;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.Authenticator;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.PasswordAuthentication;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;

/**
 * {@link HttpTransport} backed by {@link HttpURLConnection}. Works on every Java version from 8 up.
 */
final class UrlConnectionTransport implements HttpTransport {

    /** Largest response body read when the request sets no limit of its own. */
    static final int DEFAULT_MAX_RESPONSE_BYTES = 4 * 1024 * 1024;

    /**
     * Most requests with a deadline running on worker threads at once in this JVM. Beyond that a
     * request runs on the caller's thread, with its deadline enforced by closing the connection.
     */
    static final int MAX_WORKERS = 64;

    /**
     * Most requests in flight to one host (and port) at once in this JVM. A further request to that host
     * waits for one of them to finish, until its own deadline; so one server that does not answer, for
     * example a tenant's, holds at most this many connections and worker threads.
     */
    static final int MAX_PER_HOST = 32;

    /** The overall limit per request the library uses by default. */
    static final Duration DEFAULT_REQUEST_TIMEOUT = Duration.ofSeconds(60);

    /** Requests in flight per host:port; an entry is removed when its count drops to zero. Guarded by itself. */
    private static final Map<String, int[]> IN_FLIGHT = new java.util.HashMap<String, int[]>();

    /** Ends requests that run on the caller's thread at their deadline. Only hands work to short-lived threads. */
    private static final class Watchdog {
        static final java.util.concurrent.ScheduledThreadPoolExecutor EXECUTOR =
                new java.util.concurrent.ScheduledThreadPoolExecutor(1, new ThreadFactory() {
                    @Override
                    public Thread newThread(Runnable r) {
                        return daemon(r, "oauth-service-client-http-deadline");
                    }
                });

        static {
            EXECUTOR.setRemoveOnCancelPolicy(true);
            EXECUTOR.setKeepAliveTime(30, TimeUnit.SECONDS);
            EXECUTOR.allowCoreThreadTimeOut(true);
        }
    }

    /**
     * Runs requests that have an overall deadline, so the caller can stop waiting at the deadline
     * however the server behaves. Daemon threads with this library's class loader as context loader,
     * ending after 30 seconds idle, so they never pin an application's class loader.
     */
    private static final class Workers {
        static final ThreadPoolExecutor EXECUTOR = new ThreadPoolExecutor(0, MAX_WORKERS, 30, TimeUnit.SECONDS,
                new SynchronousQueue<Runnable>(), new ThreadFactory() {
                    private final AtomicInteger count = new AtomicInteger();

                    @Override
                    public Thread newThread(Runnable r) {
                        return daemon(r, "oauth-service-client-http-" + count.incrementAndGet());
                    }
                });
    }

    /** Java 9+ {@code Thread(ThreadGroup, Runnable, String, long, boolean inheritThreadLocals)}, or null on 8. */
    private static final java.lang.reflect.Constructor<Thread> NO_INHERIT = noInheritConstructor();

    /** On Java 8 only: {@code Thread.inheritableThreadLocals}, cleared on new threads; null if unavailable. */
    private static final java.lang.reflect.Field INHERITED_LOCALS = NO_INHERIT != null ? null : inheritedLocalsField();

    private static java.lang.reflect.Field inheritedLocalsField() {
        try {
            java.lang.reflect.Field f = Thread.class.getDeclaredField("inheritableThreadLocals");
            f.setAccessible(true);
            return f;
        } catch (ReflectiveOperationException | RuntimeException e) {
            return null;
        }
    }

    private static java.lang.reflect.Constructor<Thread> noInheritConstructor() {
        try {
            return Thread.class.getConstructor(ThreadGroup.class, Runnable.class, String.class, long.class, boolean.class);
        } catch (NoSuchMethodException e) {
            return null;
        }
    }

    /**
     * A daemon thread that keeps nothing of the thread that happened to create it: the library's class
     * loader as context loader, no inherited access-control context (created in a privileged block,
     * where the security API still exists) and no inherited thread-local values (on Java 8 they are
     * cleared by reflection; if the JVM forbids that, they stay). So a worker created during one web
     * application's request never keeps that application loaded.
     */
    static Thread daemon(final Runnable r, final String name) {
        Thread t = privileged(new java.security.PrivilegedAction<Thread>() {
            @Override
            public Thread run() {
                return newDaemon(r, name);
            }
        });
        return t != null ? t : newDaemon(r, name);
    }

    /** AccessController.doPrivileged, looked up by reflection: deprecated on newer JDKs and may be gone. */
    private static Thread privileged(java.security.PrivilegedAction<Thread> action) {
        try {
            Class<?> controller = Class.forName("java.security.AccessController");
            Object created = controller.getMethod("doPrivileged", java.security.PrivilegedAction.class).invoke(null, action);
            return created instanceof Thread ? (Thread) created : null;
        } catch (ReflectiveOperationException | RuntimeException | LinkageError e) {
            return null;
        }
    }

    private static Thread newDaemon(Runnable r, String name) {
        Thread t = null;
        if (NO_INHERIT != null) {
            try {
                t = NO_INHERIT.newInstance(null, r, name, 0L, false);
            } catch (ReflectiveOperationException | RuntimeException e) {
                t = null;
            }
        }
        if (t == null) {
            t = new Thread(r, name);
            if (INHERITED_LOCALS != null) {
                try {
                    INHERITED_LOCALS.set(t, null); // copied from the creating thread; not started yet
                } catch (ReflectiveOperationException | RuntimeException ignored) {
                    // keep them: the thread still works
                }
            }
        }
        t.setDaemon(true);
        t.setContextClassLoader(UrlConnectionTransport.class.getClassLoader());
        return t;
    }

    /** Request phases shared by the caller and the worker, so a request is never sent after the caller gave up. */
    private static final int CONNECTING = 0;
    private static final int SENDING = 1;
    private static final int ABANDONED = 2;

    /** One request's shared state: its phase, deadline, connection and sockets, so the caller can end it. */
    private static final class Call {
        final AtomicInteger phase = new AtomicInteger(CONNECTING);
        final long deadlineNanos; // 0 = none
        volatile boolean expired;
        volatile HttpURLConnection connection;
        /** The request's sockets: closing them also ends a TCP connect in progress, which disconnect() can't reach. */
        private final List<Socket> sockets = new ArrayList<Socket>();

        Call(long deadlineNanos) {
            this.deadlineNanos = deadlineNanos;
        }

        boolean pastDeadline() {
            return expired || (deadlineNanos != 0 && System.nanoTime() - deadlineNanos > 0);
        }

        /** Remembers a socket of this request; one made after the request was given up is closed at once. */
        <S extends Socket> S track(S socket) {
            boolean closeNow;
            synchronized (sockets) {
                closeNow = expired;
                if (!closeNow) {
                    sockets.add(socket);
                }
            }
            if (closeNow) {
                closeQuietly(socket);
            }
            return socket;
        }

        /**
         * Gives up on the request: it is not sent if it wasn't yet, and its connection is closed so the
         * worker stops reading. The close runs on its own short-lived thread, because closing can wait
         * until a blocked read returns.
         *
         * @return true if nothing of the request was sent
         */
        boolean abandon() {
            final List<Socket> open;
            synchronized (sockets) {
                expired = true;
                open = new ArrayList<Socket>(sockets);
            }
            boolean notSent = phase.compareAndSet(CONNECTING, ABANDONED) || phase.get() == ABANDONED;
            final HttpURLConnection c = connection;
            if (c != null || !open.isEmpty()) {
                daemon(new Runnable() {
                    @Override
                    public void run() {
                        // the sockets first: during the TCP connect disconnect() does nothing
                        for (Socket socket : open) {
                            closeQuietly(socket);
                        }
                        if (c != null) {
                            c.disconnect();
                        }
                    }
                }, "oauth-service-client-http-close").start();
            }
            return notSent;
        }
    }

    private final int connectTimeoutMs;
    private final int readTimeoutMs;
    private final long requestTimeoutMs;
    /** CAs to trust instead of the JVM's, or {@code null} for the JVM default. */
    private final TrustManager[] trustManagers;
    /**
     * Socket factory for requests without a client certificate: the library's own TLS context with the JVM's
     * trust store (or {@code trustManagers}), never the JVM-wide default factory, which other code may have
     * replaced (with one that trusts everything) and which presents {@code javax.net.ssl.keyStore}'s key.
     */
    private final SSLSocketFactory defaultSocketFactory;

    /**
     * @param requestTimeout longest one request may take in total, from waiting for a free slot to the
     *                       last byte of the answer; {@code null} for no overall limit (only the per-read
     *                       timeout, and no limit on requests in flight per host)
     * @param trustManagers  CAs to trust instead of the JVM's (e.g. a test CA); {@code null} for the JVM default
     */
    UrlConnectionTransport(Duration connectTimeout, Duration readTimeout, Duration requestTimeout,
                           TrustManager[] trustManagers) {
        this.connectTimeoutMs = toMillis(connectTimeout);
        this.readTimeoutMs = toMillis(readTimeout);
        this.requestTimeoutMs = requestTimeout == null ? 0 : Math.max(1, requestTimeout.toMillis());
        this.trustManagers = trustManagers == null ? null : trustManagers.clone();
        this.defaultSocketFactory = Tls.socketFactory(null, this.trustManagers);
    }

    @Override
    public HttpResponse execute(final HttpRequest request) throws IOException {
        long limitMs = requestTimeoutMs;
        if (request.getTimeout() != null) { // what is left of the caller's overall deadline
            long left = Math.max(1, request.getTimeout().toMillis());
            limitMs = limitMs <= 0 ? left : Math.min(limitMs, left);
        }
        if (limitMs <= 0) {
            return send(request, new Call(0));
        }
        final long timeoutMs = limitMs;
        final Call call = new Call(System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMs));
        final String host = hostKey(request.getUrl());
        acquire(host, call.deadlineNanos, timeoutMs);
        // The slot is given back exactly once: by the worker when it ran the request, or here when the
        // request never started (cancelled before a worker picked it up, or the pool refused it).
        final AtomicBoolean claimed = new AtomicBoolean();
        Future<HttpResponse> answer;
        try {
            answer = Workers.EXECUTOR.submit(new Callable<HttpResponse>() {
                @Override
                public HttpResponse call() throws IOException {
                    if (!claimed.compareAndSet(false, true)) {
                        return null; // the caller gave up before this started
                    }
                    try {
                        return send(request, call);
                    } finally {
                        release(host); // counted until the worker is really done
                    }
                }
            });
        } catch (RejectedExecutionException e) {
            claimed.set(true);
            try {
                return sendHere(request, call, timeoutMs);
            } finally {
                release(host);
            }
        } catch (RuntimeException | Error e) {
            if (claimed.compareAndSet(false, true)) {
                release(host);
            }
            throw e;
        }
        try {
            return answer.get(Math.max(0, call.deadlineNanos - System.nanoTime()), TimeUnit.NANOSECONDS);
        } catch (TimeoutException e) {
            if (giveUp(answer, call, claimed, host)) {
                throw new RequestNotSentException("Could not connect within " + timeoutMs + " ms",
                        new SocketTimeoutException("connect timed out"));
            }
            throw new SocketTimeoutException("Request took longer than " + timeoutMs + " ms");
        } catch (InterruptedException e) {
            giveUp(answer, call, claimed, host);
            Thread.currentThread().interrupt();
            throw new InterruptedIOException("Interrupted while waiting for the response");
        } catch (ExecutionException e) {
            Throwable cause = e.getCause();
            if (cause instanceof IOException) {
                throw (IOException) cause;
            }
            if (cause instanceof RuntimeException) {
                throw (RuntimeException) cause;
            }
            if (cause instanceof Error) {
                throw (Error) cause;
            }
            throw new IOException(cause);
        }
    }

    /**
     * Stops waiting for a request: it is not sent if it wasn't yet, and its slot is given back here if
     * no worker started it.
     *
     * @return true if nothing of the request was sent
     */
    private static boolean giveUp(Future<HttpResponse> answer, Call call, AtomicBoolean claimed, String host) {
        answer.cancel(false);
        if (claimed.compareAndSet(false, true)) {
            call.abandon();
            release(host);
            return true;
        }
        return call.abandon();
    }

    /** All workers busy: run on this thread, and close the connection at the deadline. */
    private HttpResponse sendHere(HttpRequest request, final Call call, long timeoutMs) throws IOException {
        long delay = Math.max(0, call.deadlineNanos - System.nanoTime());
        java.util.concurrent.ScheduledFuture<?> deadline = Watchdog.EXECUTOR.schedule(new Runnable() {
            @Override
            public void run() {
                call.abandon(); // closes the connection on a short-lived thread
            }
        }, delay, TimeUnit.NANOSECONDS);
        try {
            return send(request, call);
        } catch (IOException e) {
            if (!call.expired) {
                throw e;
            }
            SocketTimeoutException timeout;
            if (call.phase.get() == ABANDONED) { // stalled in connect, proxy tunnel or TLS handshake
                timeout = new SocketTimeoutException("connect timed out");
                timeout.initCause(e);
                throw new RequestNotSentException("Could not connect within " + timeoutMs + " ms", timeout);
            }
            timeout = new SocketTimeoutException("Request took longer than " + timeoutMs + " ms");
            timeout.initCause(e);
            throw timeout;
        } finally {
            deadline.cancel(false);
        }
    }

    /** host:port of a URL, the unit that {@link #MAX_PER_HOST} counts. */
    private static String hostKey(String url) throws IOException {
        URL u = new URL(url);
        int port = u.getPort() < 0 ? u.getDefaultPort() : u.getPort();
        return u.getHost().toLowerCase(java.util.Locale.ROOT) + ":" + port;
    }

    /** Takes a slot for {@code host}, waiting for a free one until the deadline. */
    private static void acquire(String host, long deadlineNanos, long timeoutMs) throws IOException {
        synchronized (IN_FLIGHT) {
            while (true) {
                int[] count = IN_FLIGHT.get(host); // looked up again after every wait: it may have been removed
                if (count == null) {
                    IN_FLIGHT.put(host, new int[] {1});
                    return;
                }
                if (count[0] < MAX_PER_HOST) {
                    count[0]++;
                    return;
                }
                long left = deadlineNanos - System.nanoTime();
                if (left <= 0) {
                    SocketTimeoutException timeout = new SocketTimeoutException("no free slot within " + timeoutMs + " ms");
                    throw new RequestNotSentException("Too many requests in flight to " + host + " (" + MAX_PER_HOST
                            + "); none finished within " + timeoutMs + " ms", timeout);
                }
                try {
                    TimeUnit.NANOSECONDS.timedWait(IN_FLIGHT, left);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new InterruptedIOException("Interrupted while waiting for a free slot to " + host);
                }
            }
        }
    }

    private static void release(String host) {
        synchronized (IN_FLIGHT) {
            int[] count = IN_FLIGHT.get(host);
            if (count != null && --count[0] <= 0) {
                IN_FLIGHT.remove(host);
            }
            IN_FLIGHT.notifyAll();
        }
    }

    /** Requests in flight to {@code host:port} in this JVM; for tests. */
    static int inFlight(String hostAndPort) {
        synchronized (IN_FLIGHT) {
            int[] count = IN_FLIGHT.get(hostAndPort);
            return count == null ? 0 : count[0];
        }
    }

    /** True while {@code host:port} has an entry in the in-flight table; for tests. */
    static boolean tracked(String hostAndPort) {
        synchronized (IN_FLIGHT) {
            return IN_FLIGHT.containsKey(hostAndPort);
        }
    }

    /** Worker threads running a request right now; for tests. */
    static int busyWorkers() {
        return Workers.EXECUTOR.getActiveCount();
    }

    /** The overall limit per request in milliseconds, 0 for none; for tests. */
    long requestTimeoutMillis() {
        return requestTimeoutMs;
    }

    private HttpResponse send(HttpRequest request, Call call) throws IOException {
        URL url = new URL(request.getUrl());
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        call.connection = conn;
        try {
            return send(conn, url, request, call);
        } finally {
            conn.disconnect();
        }
    }

    private HttpResponse send(HttpURLConnection conn, URL url, HttpRequest request, Call call) throws IOException {
        if (conn instanceof HttpsURLConnection) {
            HttpsURLConnection https = (HttpsURLConnection) conn;
            // a new factory per client certificate: the JDK reuses a kept-alive connection only with the
            // same factory, so a connection made with one tenant's certificate never carries another's request
            SSLSocketFactory factory = request.getClientCertificate() != null
                    ? Tls.socketFactory(request.getClientCertificate(), trustManagers) : defaultSocketFactory;
            https.setSSLSocketFactory(new CallSocketFactory(factory, call));
            // the JDK's own host name check decides; a lenient JVM-wide default verifier is never asked
            https.setHostnameVerifier(NO_EXCEPTIONS);
        }
        refuseServerAuthentication(conn);
        conn.setConnectTimeout(connectTimeoutMs);
        conn.setReadTimeout(readTimeoutMs);
        conn.setInstanceFollowRedirects(false);
        conn.setUseCaches(false);
        conn.setRequestMethod(request.getMethod());
        for (Map.Entry<String, String> h : request.getHeaders().entrySet()) {
            try {
                conn.setRequestProperty(h.getKey(), h.getValue());
            } catch (IllegalArgumentException e) {
                // the JDK's message quotes the value, which may be a credential: leave it out
                throw new RequestNotSentException("Header " + String.valueOf(h.getKey()).replaceAll("[\\p{Cc}\\p{Cf}]", "?")
                        + " has characters not allowed in an HTTP header", null);
            }
        }
        byte[] body = request.getBody();
        if (body != null) {
            conn.setDoOutput(true);
            if (!request.isResendable()) {
                // Turns off the JDK's silent POST retry, which would send a used code or refresh token
                // again. The cost: the body of a 401 answer can't be read (the status still is).
                conn.setFixedLengthStreamingMode(body.length);
            }
        }
        try {
            conn.connect(); // TCP, proxy tunnel and TLS handshake; nothing of the request is sent yet
        } catch (IOException e) {
            throw new RequestNotSentException("Could not connect to " + url.getHost()
                    + (url.getPort() < 0 ? "" : ":" + url.getPort()) + ": " + e, e);
        }
        if (!call.phase.compareAndSet(CONNECTING, SENDING)) {
            throw new RequestNotSentException("Request abandoned at its deadline before it was sent", null);
        }
        if (body != null) {
            OutputStream out = conn.getOutputStream();
            try {
                out.write(body);
            } finally {
                out.close();
            }
        }
        int status = conn.getResponseCode();
        InputStream in = status >= 400 ? conn.getErrorStream() : conn.getInputStream();
        int limit = request.getMaxResponseBytes() > 0 ? request.getMaxResponseBytes() : DEFAULT_MAX_RESPONSE_BYTES;
        byte[] bytes = in == null ? new byte[0] : readBody(in, limit, call);
        return new HttpResponse(status, conn.getHeaderFields(), bytes);
    }

    private static byte[] readBody(InputStream in, int limit, Call call) throws IOException {
        try {
            ByteArrayOutputStream buf = new ByteArrayOutputStream();
            byte[] chunk = new byte[8192];
            int n;
            while ((n = in.read(chunk)) != -1) {
                if (call.pastDeadline()) { // a server sending its answer slowly does not keep this thread
                    throw new SocketTimeoutException("Response not complete within the request timeout");
                }
                if (buf.size() + n > limit) {
                    throw new IOException("Response body exceeds " + limit + " bytes");
                }
                buf.write(chunk, 0, n);
            }
            return buf.toByteArray();
        } finally {
            in.close();
        }
    }

    /** Never accepts a host name the certificate doesn't match: only the JDK's own check (HTTPS identification) counts. */
    private static final HostnameVerifier NO_EXCEPTIONS = new HostnameVerifier() {
        @Override
        public boolean verify(String hostname, SSLSession session) {
            return false;
        }
    };

    /**
     * Answers proxy logins from the JVM's default {@link Authenticator} and nothing else: without it, a 401
     * with {@code WWW-Authenticate: Basic} from a service would make the JDK ask the application's
     * Authenticator and send what it answers (for example the proxy password) to the service.
     */
    private static final Authenticator PROXY_ONLY = new Authenticator() {
        @Override
        protected PasswordAuthentication getPasswordAuthentication() {
            if (getRequestorType() != RequestorType.PROXY) {
                return null;
            }
            return Authenticator.requestPasswordAuthentication(getRequestingHost(), getRequestingSite(),
                    getRequestingPort(), getRequestingProtocol(), getRequestingPrompt(), getRequestingScheme(),
                    getRequestingURL(), RequestorType.PROXY);
        }
    };

    /** {@code HttpURLConnection.setAuthenticator}, Java 9 and later; {@code null} on Java 8. */
    private static final Method SET_AUTHENTICATOR = setAuthenticatorMethod();

    private static Method setAuthenticatorMethod() {
        try {
            return HttpURLConnection.class.getMethod("setAuthenticator", Authenticator.class);
        } catch (NoSuchMethodException | RuntimeException e) {
            return null; // Java 8: no per-connection Authenticator
        }
    }

    /**
     * Keeps the JVM's default Authenticator away from server logins on this connection (Java 9 and later).
     * On Java 8 only the fixed-length requests (every POST) are safe: the JDK doesn't answer a 401 for them.
     */
    private static void refuseServerAuthentication(HttpURLConnection conn) throws IOException {
        if (SET_AUTHENTICATOR == null) {
            return;
        }
        try {
            SET_AUTHENTICATOR.invoke(conn, PROXY_ONLY);
        } catch (IllegalAccessException | InvocationTargetException | RuntimeException e) {
            throw new RequestNotSentException("Cannot keep the JVM's Authenticator away from this request: " + e, e);
        }
    }

    static boolean refusesServerAuthentication() {
        return SET_AUTHENTICATOR != null;
    }

    private static void closeQuietly(Socket socket) {
        try {
            socket.close();
        } catch (IOException | RuntimeException ignored) {
            // closing to give up: nothing more to do
        }
    }

    /**
     * Makes this request's sockets through the TLS factory and hands each to the {@link Call}, so the call
     * can close them at its deadline. The TCP socket is a plain one the JDK connects and then layers TLS
     * over: closing it ends a connect or TLS handshake in progress at once. Every TLS socket checks the host name itself (HTTPS
     * endpoint identification).
     */
    static final class CallSocketFactory extends SSLSocketFactory {

        private final SSLSocketFactory tls;
        private final Call call;

        CallSocketFactory(SSLSocketFactory tls, Call call) {
            this.tls = tls;
            this.call = call;
        }

        /** For tests: a factory whose sockets nothing tracks. */
        static CallSocketFactory untracked(SSLSocketFactory tls) {
            return new CallSocketFactory(tls, new Call(0));
        }

        @Override
        public String[] getDefaultCipherSuites() {
            return tls.getDefaultCipherSuites();
        }

        @Override
        public String[] getSupportedCipherSuites() {
            return tls.getSupportedCipherSuites();
        }

        /** The unconnected TCP socket the JDK connects (and tunnels through a proxy) before layering TLS over it. */
        @Override
        public Socket createSocket() {
            return call.track(new Socket());
        }

        @Override
        public Socket createSocket(Socket s, String host, int port, boolean autoClose) throws IOException {
            call.track(s);
            return call.track(identifyHost(tls.createSocket(s, host, port, autoClose)));
        }

        @Override
        public Socket createSocket(String host, int port) throws IOException {
            return call.track(identifyHost(tls.createSocket(host, port)));
        }

        @Override
        public Socket createSocket(String host, int port, InetAddress localHost, int localPort) throws IOException {
            return call.track(identifyHost(tls.createSocket(host, port, localHost, localPort)));
        }

        @Override
        public Socket createSocket(InetAddress host, int port) throws IOException {
            return call.track(identifyHost(tls.createSocket(host, port)));
        }

        @Override
        public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort) throws IOException {
            return call.track(identifyHost(tls.createSocket(address, port, localAddress, localPort)));
        }

        private static Socket identifyHost(Socket socket) {
            if (socket instanceof SSLSocket) {
                SSLSocket ssl = (SSLSocket) socket;
                SSLParameters params = ssl.getSSLParameters();
                params.setEndpointIdentificationAlgorithm("HTTPS");
                ssl.setSSLParameters(params);
            }
            return socket;
        }
    }

    private static int toMillis(Duration d) {
        if (d == null) {
            return 0;
        }
        long ms = d.toMillis();
        return ms > Integer.MAX_VALUE ? Integer.MAX_VALUE : (int) Math.max(0, ms);
    }
}
