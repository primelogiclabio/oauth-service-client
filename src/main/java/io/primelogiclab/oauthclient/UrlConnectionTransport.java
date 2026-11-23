package io.primelogiclab.oauthclient;

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.FilterInputStream;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.Authenticator;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.PasswordAuthentication;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.nio.channels.SocketChannel;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
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

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;

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

    /** Most client certificates whose socket factory is kept per transport. */
    static final long MAX_CERTIFICATE_FACTORIES = 1000;

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

    /**
     * One request's shared state: its phase, deadline, connection and the sockets it is using, so the caller
     * can end it. A connection kept alive passes from request to request, so a request closes a socket only
     * while it is still that socket's user, and nothing once it has finished.
     */
    static final class Call {
        final AtomicInteger phase = new AtomicInteger(CONNECTING);
        final long deadlineNanos; // 0 = none
        volatile boolean expired;
        volatile HttpURLConnection connection;
        /**
         * The sockets this request has used: closing them also ends a TCP connect in progress, which
         * disconnect() can't reach. Guarded by itself, as is {@code finished}.
         */
        private final List<TrackedSocket> sockets = new ArrayList<TrackedSocket>();
        private boolean finished;

        Call(long deadlineNanos) {
            this.deadlineNanos = deadlineNanos;
        }

        boolean pastDeadline() {
            return expired || (deadlineNanos != 0 && System.nanoTime() - deadlineNanos > 0);
        }

        /**
         * Notes that {@code socket} is being used for this request: made, read or written.
         *
         * @return false if the request was given up, so the socket is to be closed
         */
        boolean using(TrackedSocket socket) {
            synchronized (sockets) {
                if (expired) {
                    return false;
                }
                if (!finished && !sockets.contains(socket)) {
                    sockets.add(socket);
                }
                return true;
            }
        }

        /**
         * Gives up on the request: it is not sent if it wasn't yet, and the sockets it is using are closed so
         * the worker stops reading. The close runs on its own short-lived thread, because closing can wait
         * until a blocked read returns. Once the request has finished, nothing is closed: its connection may
         * be carrying another request by then.
         *
         * @return true if nothing of the request was sent
         */
        boolean abandon() {
            final List<TrackedSocket> open;
            final HttpURLConnection c;
            synchronized (sockets) {
                expired = true;
                open = finished ? Collections.<TrackedSocket>emptyList() : new ArrayList<TrackedSocket>(sockets);
                c = finished ? null : connection;
            }
            boolean notSent = phase.compareAndSet(CONNECTING, ABANDONED) || phase.get() == ABANDONED;
            if (c != null || !open.isEmpty()) {
                daemon(new Runnable() {
                    @Override
                    public void run() {
                        // the sockets first: during the TCP connect disconnect() does nothing. A socket another
                        // request has used since is left alone; disconnect() then closes at most an idle one
                        for (TrackedSocket socket : open) {
                            socket.closeFor(Call.this);
                        }
                        if (c != null) {
                            c.disconnect();
                        }
                    }
                }, "oauth-service-client-http-close").start();
            }
            return notSent;
        }

        /**
         * Closes the sockets this request is still using, on this thread, so a connection it leaves half-used
         * is never kept alive for another request.
         */
        void closeSockets() {
            List<TrackedSocket> open;
            synchronized (sockets) {
                open = finished ? Collections.<TrackedSocket>emptyList() : new ArrayList<TrackedSocket>(sockets);
            }
            for (TrackedSocket socket : open) {
                socket.closeFor(this);
            }
        }

        /**
         * Ends the request: the sockets it used are no longer its own, so neither its deadline nor anything
         * else of it closes them.
         */
        void finish() {
            List<TrackedSocket> used;
            synchronized (sockets) {
                finished = true;
                used = new ArrayList<TrackedSocket>(sockets);
                sockets.clear();
            }
            for (TrackedSocket socket : used) {
                socket.release(this);
            }
        }
    }

    /** The request the current thread is sending, for the sockets it uses; set by {@link #send(HttpRequest, Call)}. */
    private static final ThreadLocal<Call> CURRENT = new ThreadLocal<Call>();

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
    private final TrackingSocketFactory defaultSocketFactory;
    /**
     * Socket factories per client certificate, so repeated calls with one key reuse its TLS context, sessions
     * and kept-alive connections. Keyed by the key object's identity (weak keys): a different key, another
     * tenant's say, never shares one, and an entry goes when its key is no longer used.
     */
    private final Cache<ClientKey, TrackingSocketFactory> certificateFactories =
            Caffeine.newBuilder().weakKeys().maximumSize(MAX_CERTIFICATE_FACTORIES).build();

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
        this.defaultSocketFactory = new TrackingSocketFactory(Tls.socketFactory(null, this.trustManagers),
                connectTimeoutMs);
    }

    @Override
    public HttpResponse execute(final HttpRequest request) throws IOException {
        if ("PATCH".equals(request.getMethod())) {
            return patchTransport().execute(request); // HttpURLConnection refuses PATCH
        }
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
    static String hostKey(String url) throws IOException {
        URL u = new URL(url);
        int port = u.getPort() < 0 ? u.getDefaultPort() : u.getPort();
        return u.getHost().toLowerCase(java.util.Locale.ROOT) + ":" + port;
    }

    /** Takes a slot for {@code host}, waiting for a free one until the deadline. */
    static void acquire(String host, long deadlineNanos, long timeoutMs) throws IOException {
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

    static void release(String host) {
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

    /** For tests: makes {@code call} (or, with {@code null}, none) the request this thread is sending. */
    static void sendingFor(Call call) {
        if (call == null) {
            CURRENT.remove();
        } else {
            CURRENT.set(call);
        }
    }

    /** Worker threads running a request right now; for tests. */
    static int busyWorkers() {
        return Workers.EXECUTOR.getActiveCount();
    }

    /** The class that sends PATCH through java.net.http; compiled on JDK 11+ only (src/main/java11). */
    static final String PATCH_TRANSPORT = "io.primelogiclab.oauthclient.Java11PatchTransport";
    private static final boolean PATCH_SUPPORTED = patchClassAvailable();
    private volatile HttpTransport patch;

    /** True when this runtime and build can send PATCH: Java 11 or later, and a jar built on JDK 11+. */
    static boolean patchSupported() {
        return PATCH_SUPPORTED;
    }

    private static boolean patchClassAvailable() {
        try {
            Class.forName("java.net.http.HttpClient"); // first: on Java 8 the version-55 class is never touched
            Class.forName(PATCH_TRANSPORT, false, UrlConnectionTransport.class.getClassLoader());
            return true;
        } catch (ClassNotFoundException | LinkageError | RuntimeException e) {
            return false;
        }
    }

    /** The PATCH transport, made on first use with this transport's timeouts and trust. */
    HttpTransport patchTransport() throws IOException {
        HttpTransport t = patch;
        if (t == null) {
            synchronized (this) {
                t = patch;
                if (t == null) {
                    t = newPatchTransport();
                    patch = t;
                }
            }
        }
        return t;
    }

    private HttpTransport newPatchTransport() throws IOException {
        if (!PATCH_SUPPORTED) {
            throw new RequestNotSentException("PATCH needs Java 11 or later (it is sent with java.net.http)", null);
        }
        try {
            java.lang.reflect.Constructor<?> c = Class.forName(PATCH_TRANSPORT)
                    .getDeclaredConstructor(long.class, long.class, TrustManager[].class);
            return (HttpTransport) c.newInstance((long) connectTimeoutMs, requestTimeoutMs, trustManagers);
        } catch (java.lang.reflect.InvocationTargetException e) {
            Throwable cause = e.getCause();
            if (cause instanceof RuntimeException) {
                throw (RuntimeException) cause; // e.g. TLS couldn't be set up: OAuthServiceException
            }
            throw new IOException("Cannot set up the PATCH transport: " + cause, cause);
        } catch (ReflectiveOperationException | LinkageError e) {
            throw new RequestNotSentException("PATCH needs Java 11 or later (it is sent with java.net.http): " + e, e);
        }
    }

    private static final java.util.logging.Logger LOG = java.util.logging.Logger.getLogger(UrlConnectionTransport.class.getName());
    private static final AtomicBoolean COOKIE_WARNING = new AtomicBoolean();

    /**
     * Warns once when the application installed a JVM-wide {@link java.net.CookieHandler}: HttpURLConnection
     * then stores and sends cookies for every call in the JVM, so cookies from one tenant's calls can go out
     * with another's to the same host. There's no way to turn that off per connection.
     */
    private static void warnAboutJvmCookies() {
        if (java.net.CookieHandler.getDefault() != null && COOKIE_WARNING.compareAndSet(false, true)) {
            LOG.warning("A JVM-wide CookieHandler is installed (CookieHandler.setDefault): HttpURLConnection shares its "
                    + "cookies across all calls, so cookies from one tenant's service can go out with another tenant's "
                    + "calls to the same host. oauth-service-client can't turn this off; remove the CookieHandler if "
                    + "tenants share service hosts.");
        }
    }

    /** For tests: lets the cookie warning show again. */
    static void resetCookieWarning() {
        COOKIE_WARNING.set(false);
    }

    /** The TLS socket factory presenting {@code certificate}, made once per key and kept. */
    TrackingSocketFactory socketFactoryFor(final ClientKey certificate) {
        return certificateFactories.get(certificate,
                key -> new TrackingSocketFactory(Tls.socketFactory(key, trustManagers), connectTimeoutMs));
    }

    /** The overall limit per request in milliseconds, 0 for none; for tests. */
    long requestTimeoutMillis() {
        return requestTimeoutMs;
    }

    /**
     * Sends the request on a connection the JDK keeps alive, per host and TLS socket factory: one it kept
     * from an earlier request if it has one, and keeps for a later one once the answer was read to its end. A
     * request that fails, or has a connection of its own, closes its connection instead.
     */
    private HttpResponse send(HttpRequest request, Call call) throws IOException {
        URL url = new URL(request.getUrl());
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        call.connection = conn;
        CURRENT.set(call);
        boolean answered = false;
        try {
            HttpResponse response = send(conn, url, request, call);
            answered = true;
            return response;
        } finally {
            try {
                if (!answered || request.isOwnConnection()) {
                    // the sockets first: a half-used connection is never kept alive for another request.
                    // disconnect() then closes one taken from the JDK's pool and not used yet, and takes a
                    // connection of its own out of the pool
                    call.closeSockets();
                    conn.disconnect();
                }
            } finally {
                call.finish();
                CURRENT.remove();
            }
        }
    }

    private HttpResponse send(HttpURLConnection conn, URL url, HttpRequest request, Call call) throws IOException {
        warnAboutJvmCookies();
        if (conn instanceof HttpsURLConnection) {
            HttpsURLConnection https = (HttpsURLConnection) conn;
            // a factory per client certificate: the JDK reuses a kept-alive connection only with the same
            // factory, so a connection made with one tenant's certificate never carries another's request, nor
            // one without a certificate. A request with a connection of its own gets a factory of its own
            TrackingSocketFactory factory = request.getClientCertificate() != null
                    ? socketFactoryFor(request.getClientCertificate()) : defaultSocketFactory;
            https.setSSLSocketFactory(request.isOwnConnection() ? factory.fresh() : factory);
            // the JDK's own host name check decides; a lenient JVM-wide default verifier is never asked
            https.setHostnameVerifier(NO_EXCEPTIONS);
        }
        refuseServerAuthentication(conn);
        conn.setConnectTimeout(connectTimeoutMs);
        conn.setReadTimeout(readTimeoutMs);
        conn.setInstanceFollowRedirects(false);
        conn.setUseCaches(false);
        // the JDK's own literal: a JDK comparing the method by identity still checks that a kept-alive
        // connection is open before a POST takes it
        conn.setRequestMethod(request.getMethod().intern());
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
        boolean complete = false;
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
            complete = true;
            return buf.toByteArray();
        } finally {
            if (complete) {
                in.close();
            } else {
                // the sockets first: closing the stream of a half-read answer would have the JDK read the
                // rest in the background and keep the connection alive
                call.closeSockets();
                closeQuietly(in);
            }
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

    private static void closeQuietly(Closeable closeable) {
        try {
            closeable.close();
        } catch (IOException | RuntimeException ignored) {
            // closing to give up: nothing more to do
        }
    }

    /**
     * The TLS socket factory set on every HTTPS connection: one per TLS context (the default, and one per client
     * certificate), as the JDK keeps connections alive per factory and reuses them only with the same one. Each
     * TCP socket under TLS is a {@link TrackedSocket}, whether made here or, through a proxy, by the JDK, so the
     * request using it can close it at its deadline: closing it ends a connect or TLS handshake in progress at
     * once. Every TLS socket checks the host name itself (HTTPS endpoint identification).
     */
    static final class TrackingSocketFactory extends SSLSocketFactory {

        private final SSLSocketFactory tls;
        private final int connectTimeoutMs;

        TrackingSocketFactory(SSLSocketFactory tls, int connectTimeoutMs) {
            this.tls = tls;
            this.connectTimeoutMs = connectTimeoutMs;
        }

        /** For tests: a factory whose sockets no request tracks unless one is being sent on this thread. */
        static TrackingSocketFactory untracked(SSLSocketFactory tls) {
            return new TrackingSocketFactory(tls, 0);
        }

        /**
         * A factory of its own over the same TLS context: the JDK keeps its connection for no other request,
         * while the TLS session still resumes.
         */
        TrackingSocketFactory fresh() {
            return new TrackingSocketFactory(tls, connectTimeoutMs);
        }

        @Override
        public String[] getDefaultCipherSuites() {
            return tls.getDefaultCipherSuites();
        }

        @Override
        public String[] getSupportedCipherSuites() {
            return tls.getSupportedCipherSuites();
        }

        /** The unconnected TCP socket the JDK connects before layering TLS over it (without a proxy). */
        @Override
        public Socket createSocket() {
            return TrackedSocket.adopt(new Socket());
        }

        /** TLS over {@code s}; through a proxy, {@code s} is a socket the JDK made and tunnelled itself. */
        @Override
        public Socket createSocket(Socket s, String host, int port, boolean autoClose) throws IOException {
            Socket tcp = s instanceof TrackedSocket ? s : TrackedSocket.adopt(s);
            return identifyHost(tls.createSocket(tcp, host, port, autoClose));
        }

        @Override
        public Socket createSocket(String host, int port) throws IOException {
            return direct(new InetSocketAddress(host, port), null, host, port);
        }

        @Override
        public Socket createSocket(String host, int port, InetAddress localHost, int localPort) throws IOException {
            return direct(new InetSocketAddress(host, port), new InetSocketAddress(localHost, localPort), host, port);
        }

        @Override
        public Socket createSocket(InetAddress host, int port) throws IOException {
            return direct(new InetSocketAddress(host, port), null, host.getHostName(), port);
        }

        @Override
        public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort) throws IOException {
            return direct(new InetSocketAddress(address, port), new InetSocketAddress(localAddress, localPort),
                    address.getHostName(), port);
        }

        /** A TLS socket connected straight to the host (the JDK's fallback when a proxy tunnel fails), tracked too. */
        private Socket direct(InetSocketAddress remote, InetSocketAddress local, String host, int port) throws IOException {
            TrackedSocket tcp = TrackedSocket.adopt(new Socket());
            try {
                if (local != null) {
                    tcp.bind(local);
                }
                tcp.connect(remote, connectTimeoutMs);
                return identifyHost(tls.createSocket(tcp, host, port, true));
            } catch (IOException | RuntimeException e) {
                closeQuietly(tcp);
                throw e;
            }
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

    /**
     * The TCP socket under a TLS connection, with the request that last used it: every read and write marks
     * the current thread's request as its user. When the JDK keeps the connection alive and hands it to the
     * next request, that request becomes its user at its first read or write, and the one before, should its
     * deadline come late, leaves it alone. Should a request close it before then, the next one finds a dead
     * connection, which the JDK replaces before sending anything (a POST) or resends on (GET, PUT, DELETE).
     * Delegates to the real socket; its own is never connected.
     */
    static final class TrackedSocket extends Socket {

        private final Socket socket;
        private final Object lock = new Object();
        private Call user; // guarded by lock
        private InputStream input; // guarded by lock
        private OutputStream output; // guarded by lock

        private TrackedSocket(Socket socket) {
            this.socket = socket;
        }

        /** {@code socket}, tracked for the current thread's request; closed at once if that request was given up. */
        static TrackedSocket adopt(Socket socket) {
            TrackedSocket tracked = new TrackedSocket(socket);
            if (!tracked.mark()) {
                closeQuietly(socket);
            }
            return tracked;
        }

        /**
         * Marks the current thread's request, if any, as this socket's user.
         *
         * @return false if that request was given up
         */
        private boolean mark() {
            Call call = CURRENT.get();
            if (call == null) {
                return true; // the JDK's own threads, closing or cleaning up an idle connection
            }
            synchronized (lock) {
                if (user == call && !call.expired) {
                    return true;
                }
                if (!call.using(this)) {
                    return false;
                }
                user = call;
                return true;
            }
        }

        /** Before every read and write: marks the user, and refuses I/O for a request that was given up. */
        private void claim() throws IOException {
            if (!mark()) {
                closeQuietly(socket);
                throw new SocketException("Request given up at its deadline");
            }
        }

        /**
         * Closes the socket if {@code call} is still its user.
         *
         * @return true if it was closed
         */
        boolean closeFor(Call call) {
            synchronized (lock) {
                if (user != call) {
                    return false;
                }
                closeQuietly(socket);
                return true;
            }
        }

        /** {@code call} is done with this socket: it no longer counts as its user. */
        void release(Call call) {
            synchronized (lock) {
                if (user == call) {
                    user = null;
                }
            }
        }

        /** The request using this socket, or {@code null}; for tests. */
        Call user() {
            synchronized (lock) {
                return user;
            }
        }

        @Override
        public InputStream getInputStream() throws IOException {
            synchronized (lock) {
                if (input == null) {
                    input = new FilterInputStream(socket.getInputStream()) {
                        @Override
                        public int read() throws IOException {
                            claim();
                            return in.read();
                        }

                        @Override
                        public int read(byte[] b, int off, int len) throws IOException {
                            claim();
                            return in.read(b, off, len);
                        }

                        @Override
                        public long skip(long n) throws IOException {
                            claim();
                            return in.skip(n);
                        }
                    };
                }
                return input;
            }
        }

        @Override
        public OutputStream getOutputStream() throws IOException {
            synchronized (lock) {
                if (output == null) {
                    output = new FilterOutputStream(socket.getOutputStream()) {
                        @Override
                        public void write(int b) throws IOException {
                            claim();
                            out.write(b);
                        }

                        @Override
                        public void write(byte[] b, int off, int len) throws IOException {
                            claim();
                            out.write(b, off, len);
                        }

                        @Override
                        public void flush() throws IOException {
                            claim();
                            out.flush();
                        }
                    };
                }
                return output;
            }
        }

        @Override
        public void connect(SocketAddress endpoint) throws IOException {
            socket.connect(endpoint);
        }

        @Override
        public void connect(SocketAddress endpoint, int timeout) throws IOException {
            socket.connect(endpoint, timeout);
        }

        @Override
        public void bind(SocketAddress bindpoint) throws IOException {
            socket.bind(bindpoint);
        }

        @Override
        public void close() throws IOException {
            socket.close();
        }

        @Override
        public void shutdownInput() throws IOException {
            socket.shutdownInput();
        }

        @Override
        public void shutdownOutput() throws IOException {
            socket.shutdownOutput();
        }

        @Override
        public InetAddress getInetAddress() {
            return socket.getInetAddress();
        }

        @Override
        public InetAddress getLocalAddress() {
            return socket.getLocalAddress();
        }

        @Override
        public int getPort() {
            return socket.getPort();
        }

        @Override
        public int getLocalPort() {
            return socket.getLocalPort();
        }

        @Override
        public SocketAddress getRemoteSocketAddress() {
            return socket.getRemoteSocketAddress();
        }

        @Override
        public SocketAddress getLocalSocketAddress() {
            return socket.getLocalSocketAddress();
        }

        @Override
        public SocketChannel getChannel() {
            return socket.getChannel();
        }

        @Override
        public void setTcpNoDelay(boolean on) throws SocketException {
            socket.setTcpNoDelay(on);
        }

        @Override
        public boolean getTcpNoDelay() throws SocketException {
            return socket.getTcpNoDelay();
        }

        @Override
        public void setSoLinger(boolean on, int linger) throws SocketException {
            socket.setSoLinger(on, linger);
        }

        @Override
        public int getSoLinger() throws SocketException {
            return socket.getSoLinger();
        }

        @Override
        public void sendUrgentData(int data) throws IOException {
            socket.sendUrgentData(data);
        }

        @Override
        public void setOOBInline(boolean on) throws SocketException {
            socket.setOOBInline(on);
        }

        @Override
        public boolean getOOBInline() throws SocketException {
            return socket.getOOBInline();
        }

        @Override
        public void setSoTimeout(int timeout) throws SocketException {
            socket.setSoTimeout(timeout);
        }

        @Override
        public int getSoTimeout() throws SocketException {
            return socket.getSoTimeout();
        }

        @Override
        public void setSendBufferSize(int size) throws SocketException {
            socket.setSendBufferSize(size);
        }

        @Override
        public int getSendBufferSize() throws SocketException {
            return socket.getSendBufferSize();
        }

        @Override
        public void setReceiveBufferSize(int size) throws SocketException {
            socket.setReceiveBufferSize(size);
        }

        @Override
        public int getReceiveBufferSize() throws SocketException {
            return socket.getReceiveBufferSize();
        }

        @Override
        public void setKeepAlive(boolean on) throws SocketException {
            socket.setKeepAlive(on);
        }

        @Override
        public boolean getKeepAlive() throws SocketException {
            return socket.getKeepAlive();
        }

        @Override
        public void setTrafficClass(int tc) throws SocketException {
            socket.setTrafficClass(tc);
        }

        @Override
        public int getTrafficClass() throws SocketException {
            return socket.getTrafficClass();
        }

        @Override
        public void setReuseAddress(boolean on) throws SocketException {
            socket.setReuseAddress(on);
        }

        @Override
        public boolean getReuseAddress() throws SocketException {
            return socket.getReuseAddress();
        }

        @Override
        public void setPerformancePreferences(int connectionTime, int latency, int bandwidth) {
            socket.setPerformancePreferences(connectionTime, latency, bandwidth);
        }

        @Override
        public boolean isConnected() {
            return socket.isConnected();
        }

        @Override
        public boolean isBound() {
            return socket.isBound();
        }

        @Override
        public boolean isClosed() {
            return socket.isClosed();
        }

        @Override
        public boolean isInputShutdown() {
            return socket.isInputShutdown();
        }

        @Override
        public boolean isOutputShutdown() {
            return socket.isOutputShutdown();
        }

        @Override
        public String toString() {
            return socket.toString();
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
