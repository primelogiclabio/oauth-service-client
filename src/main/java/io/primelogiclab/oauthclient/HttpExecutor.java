package io.primelogiclab.oauthclient;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.SocketTimeoutException;
import java.time.Clock;
import java.time.Duration;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Pattern;

import javax.net.ssl.SSLHandshakeException;

/**
 * Runs requests through the transport with retries and exponential backoff; a failed TLS handshake is never
 * retried, since it fails the same way again. Honors {@code Retry-After} (seconds or HTTP-date), capped at
 * {@link #MAX_RETRY_AFTER_MS}. With a call timeout, all attempts and the pauses
 * between them end within it: later attempts get only the time that is left (see {@link HttpRequest#withTimeout}).
 * Every URL is checked to be https before anything is sent. Copied from oauth-connector.
 */
final class HttpExecutor {

    /** When a failed attempt may be repeated. */
    enum Retry {
        /** Never: the request reaches the server at most once. */
        NEVER,
        /**
         * Only when the server certainly did not process the request: the connection could not be made, or
         * it answered 429, or 503 with Retry-After. Token requests use this: some vendors cap token requests
         * (Vertex: 10 per 8 hours), and a resent rotating refresh token can revoke the whole token family.
         */
        IF_NOT_PROCESSED,
        /**
         * Only when nothing was sent (the connection could not be made), or the server answered 429 or 503
         * with Retry-After, asking to come back. Service calls use this unless the caller asks for more.
         */
        BUSY_OR_NOT_SENT,
        /** On any transport error, 429 or 5xx (idempotent requests). */
        ALWAYS
    }

    interface Sleeper {
        void sleep(long millis) throws InterruptedException;
    }

    static final Sleeper THREAD_SLEEPER = new Sleeper() {
        @Override
        public void sleep(long millis) throws InterruptedException {
            Thread.sleep(millis);
        }
    };

    static final long MAX_RETRY_AFTER_MS = 30000L;
    private static final Logger LOG = Logger.getLogger(HttpExecutor.class.getName());
    private static final Pattern HEADER_NAME = Pattern.compile("[!#$%&'*+.^_`|~0-9A-Za-z-]+");
    private static final Pattern HEADER_VALUE_CTL = Pattern.compile("[\\x00-\\x08\\x0a-\\x1f\\x7f]");

    private final HttpTransport transport;
    private final int maxRetries;
    private final long backoffMs;
    private final Sleeper sleeper;
    private final long callTimeoutNanos; // 0 = none
    private final Clock clock; // for Retry-After dates

    /** @param callTimeout longest one call may take with all its attempts; {@code null} for no overall limit */
    HttpExecutor(HttpTransport transport, int maxRetries, Duration backoff, Sleeper sleeper, Duration callTimeout) {
        this(transport, maxRetries, backoff, sleeper, callTimeout, Clock.systemUTC());
    }

    HttpExecutor(HttpTransport transport, int maxRetries, Duration backoff, Sleeper sleeper, Duration callTimeout,
                 Clock clock) {
        this.transport = transport;
        this.maxRetries = maxRetries;
        this.backoffMs = backoff.toMillis();
        this.sleeper = sleeper;
        this.callTimeoutNanos = callTimeout == null ? 0 : Math.max(1, callTimeout.toNanos());
        this.clock = clock;
    }

    /** The deadline for a call starting now, in {@link System#nanoTime()} terms; 0 when there's no call timeout. */
    long deadlineFromNow() {
        return callTimeoutNanos == 0 ? 0 : System.nanoTime() + callTimeoutNanos;
    }

    /**
     * Builds a new request for every attempt, so one-time values such as an assertion's {@code jti} are
     * never sent twice.
     *
     * @return the final response, which may be a non-2xx response
     * @throws OAuthServiceException if the URL isn't https (nothing is sent), or the transport fails on the last attempt
     */
    HttpResponse execute(Supplier<HttpRequest> requests, Retry retry) {
        return execute(requests, retry, deadlineFromNow());
    }

    /**
     * Like {@link #execute(Supplier, Retry)}, with every attempt and pause ending by {@code deadline}, a
     * {@link System#nanoTime()} value; 0 for none. Lets one call share its deadline across several executions
     * (a resend after the service rejected the token).
     */
    HttpResponse execute(Supplier<HttpRequest> requests, Retry retry, long deadline) {
        int attempts = retry == Retry.NEVER ? 1 : maxRetries + 1;
        long delay = Math.min(backoffMs, MAX_RETRY_AFTER_MS);
        for (int attempt = 1; ; attempt++) {
            HttpRequest request = requests.get();
            String problem = ClientInfo.urlProblem(request.getUrl());
            if (problem != null) {
                throw new OAuthServiceException("Refusing to send request: URL " + problem);
            }
            String badHeader = headerProblem(request.getHeaders());
            if (badHeader != null) {
                throw new OAuthServiceException("Refusing to send request: " + request + ": " + badHeader);
            }
            if (Thread.currentThread().isInterrupted()) {
                throw new OAuthServiceException("Interrupted before sending " + request,
                        new InterruptedIOException("the calling thread is interrupted"));
            }
            if (deadline != 0) { // every attempt gets only what is left of the call
                request = request.withTimeout(Duration.ofNanos(Math.max(1, deadline - System.nanoTime())));
            }
            HttpResponse response;
            try {
                response = transport.execute(request);
            } catch (IOException e) {
                // After a timeout the server may have the request: it is repeated only when it certainly was
                // not sent (a connect timeout) and time is left, so the call timeout bounds the whole call.
                boolean timedOut = timedOut(e);
                boolean retryable = attempt < attempts && !interrupted(e) && !tlsHandshakeFailed(e)
                        && (retry == Retry.ALWAYS || notSent(e))
                        && (!timedOut || (notSent(e) && deadline != 0))
                        && timeLeft(deadline, delay);
                if (!retryable) {
                    throw new OAuthServiceException("Request failed: " + request + ": " + Strings.safe(e.toString()), e);
                }
                LOG.log(Level.FINE, "Attempt {0} of {1} failed: {2}", new Object[] {attempt, request.toString(), Strings.safe(e.toString())});
                pause(delay);
                delay = next(delay);
                continue;
            }
            int status = response.getStatus();
            // A proxy can answer 503 after the server processed the request; only a 503 with
            // Retry-After (the server itself asking to come back) counts as "not processed".
            // a Retry-After that can't be read doesn't count as the server asking to come back
            long requested = retryAfterMillis(response.header("Retry-After"));
            boolean askedToWait = requested >= 0;
            boolean retryStatus;
            switch (retry) {
                case IF_NOT_PROCESSED:
                    retryStatus = status == 429 || (status == 503 && askedToWait);
                    break;
                case BUSY_OR_NOT_SENT:
                    retryStatus = (status == 429 || status == 503) && askedToWait;
                    break;
                default:
                    retryStatus = status == 429 || status >= 500;
                    break;
            }
            if (!retryStatus || attempt >= attempts) {
                return response;
            }
            if (askedToWait && requested > MAX_RETRY_AFTER_MS) {
                return response; // the server asked for a longer pause than the library waits: its answer goes back
            }
            long wait = askedToWait ? requested : delay;
            if (!timeLeft(deadline, wait)) {
                return response;
            }
            LOG.log(Level.FINE, "Attempt {0} of {1} returned HTTP {2}; retrying in {3} ms",
                    new Object[] {attempt, request.toString(), status, wait});
            pause(wait);
            delay = next(delay);
        }
    }

    /** True when, after pausing {@code pauseMs}, some of the call's time is still left (always without a deadline). */
    private static boolean timeLeft(long deadline, long pauseMs) {
        return deadline == 0 || deadline - System.nanoTime() - TimeUnit.MILLISECONDS.toNanos(pauseMs) > 0;
    }

    /**
     * True when the failure happened before any part of the request reached the server: only the transports'
     * own {@link RequestNotSentException} says so. A plain connection error can come from the JDK's silent
     * resend after the request was sent, so it doesn't count.
     */
    static boolean notSent(IOException e) {
        return e instanceof RequestNotSentException;
    }

    /** True if {@code e} or a cause is a timeout: the server did not answer in time. */
    private static boolean timedOut(Throwable e) {
        for (Throwable c = e; c != null; c = c.getCause()) {
            if (c instanceof SocketTimeoutException) {
                return true;
            }
        }
        return false;
    }

    /**
     * True if {@code e} or a cause is a failed TLS handshake: a rejected or missing client certificate, an
     * untrusted server certificate, no common protocol. Trying again gives the same answer, so it isn't retried.
     */
    static boolean tlsHandshakeFailed(Throwable e) {
        for (Throwable c = e; c != null; c = c.getCause()) {
            if (c instanceof SSLHandshakeException) {
                return true;
            }
        }
        return false;
    }

    /** True if {@code e} or a cause is an interruption of the calling thread, not a server problem. */
    private static boolean interrupted(Throwable e) {
        for (Throwable c = e; c != null; c = c.getCause()) {
            if (c instanceof InterruptedException
                    || (c instanceof InterruptedIOException && !(c instanceof SocketTimeoutException))) {
                return true;
            }
        }
        return Thread.currentThread().isInterrupted();
    }

    /** Doubled backoff, never longer than {@link #MAX_RETRY_AFTER_MS}. */
    private static long next(long delay) {
        return Math.min(delay * 2, MAX_RETRY_AFTER_MS);
    }

    /**
     * The pause Retry-After asks for, in milliseconds (seconds, or an HTTP-date); {@code -1} when there's no
     * header or it can't be read. Never negative otherwise, and {@link Long#MAX_VALUE} for a value too large
     * to count, so a huge one can't overflow into "retry at once".
     */
    private long retryAfterMillis(String header) {
        return retryAfterMillis(header, clock);
    }

    /** {@link #retryAfterMillis(String)} with the given clock for the HTTP-date form. */
    static long retryAfterMillis(String header, Clock clock) {
        if (header == null) {
            return -1;
        }
        String value = header.trim();
        try {
            long seconds = Math.max(0, Long.parseLong(value));
            return seconds > Long.MAX_VALUE / 1000L ? Long.MAX_VALUE : seconds * 1000L;
        } catch (NumberFormatException notSeconds) {
            // the HTTP-date form, e.g. Wed, 21 Oct 2026 07:28:00 GMT
        }
        try {
            ZonedDateTime at = ZonedDateTime.parse(value, DateTimeFormatter.RFC_1123_DATE_TIME);
            return Math.max(0, at.toInstant().toEpochMilli() - clock.millis());
        } catch (DateTimeParseException | ArithmeticException unreadable) {
            return -1;
        }
    }

    /** Why the headers can't be sent, or null: names must be RFC 7230 tokens, values free of control characters (tab aside). */
    static String headerProblem(Map<String, String> headers) {
        for (Map.Entry<String, String> h : headers.entrySet()) {
            String name = h.getKey();
            if (name == null || !HEADER_NAME.matcher(name).matches()) {
                return "header name " + Strings.safe(String.valueOf(name)) + " is not a valid HTTP header name";
            }
            String value = h.getValue();
            if (value == null || HEADER_VALUE_CTL.matcher(value).find()) {
                // never the value itself: it is often a credential
                return "header " + name + " has a value with characters not allowed in an HTTP header (a line break?)";
            }
        }
        return null;
    }

    private void pause(long millis) {
        if (millis <= 0) {
            return;
        }
        try {
            sleeper.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new OAuthServiceException("Interrupted while waiting to retry", e);
        }
    }
}
