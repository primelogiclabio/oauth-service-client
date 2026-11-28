package io.primelogiclab.oauthclient;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/** The JVM-wide limit on requests in flight per host:port: settable, first come, first served. */
@Timeout(60)
class PerHostLimitTest {

    private static final AtomicInteger HOSTS = new AtomicInteger();

    @AfterEach
    void restoreTheDefault() {
        UrlConnectionTransport.setMaxPerHost(UrlConnectionTransport.DEFAULT_MAX_PER_HOST);
    }

    @Test
    void theDefaultIs32AndTheSetterChecksItsInput() {
        assertEquals(32, UrlConnectionTransport.DEFAULT_MAX_PER_HOST);
        assertEquals(32, OAuthServiceClient.getMaxRequestsPerHost());
        IllegalArgumentException zero = assertThrows(IllegalArgumentException.class,
                () -> OAuthServiceClient.setMaxRequestsPerHost(0));
        assertTrue(zero.getMessage().contains("at least 1"), zero.getMessage());
        assertThrows(IllegalArgumentException.class, () -> OAuthServiceClient.setMaxRequestsPerHost(-1));
        assertEquals(32, OAuthServiceClient.getMaxRequestsPerHost(), "a refused value changed the limit");

        OAuthServiceClient.setMaxRequestsPerHost(7);
        assertEquals(7, OAuthServiceClient.getMaxRequestsPerHost());
        assertEquals(7, UrlConnectionTransport.maxPerHost());
    }

    @Test
    void theLimitIsHonoured() throws Exception {
        String host = host();
        OAuthServiceClient.setMaxRequestsPerHost(2);
        take(host, 1000);
        take(host, 1000);

        RequestNotSentException full = assertThrows(RequestNotSentException.class, () -> take(host, 100));
        assertTrue(full.getMessage().contains("Too many requests in flight to " + host + " (limit 2)"), full.getMessage());
        assertEquals(2, UrlConnectionTransport.inFlight(host));
        assertEquals(0, UrlConnectionTransport.waiting(host), "the request that gave up is still queued");

        UrlConnectionTransport.release(host);
        UrlConnectionTransport.release(host);
        assertFalse(UrlConnectionTransport.tracked(host), "an idle host keeps its entry");
    }

    @Test
    void waitingRequestsAreServedInTheOrderTheyCame() throws Exception {
        String host = host();
        OAuthServiceClient.setMaxRequestsPerHost(1);
        take(host, 1000);
        FutureTask<Void> first = background(() -> take(host, 20_000));
        eventually(() -> UrlConnectionTransport.waiting(host) == 1, "the first request never queued");
        FutureTask<Void> second = background(() -> take(host, 20_000));
        eventually(() -> UrlConnectionTransport.waiting(host) == 2, "the second request never queued");

        UrlConnectionTransport.release(host);
        first.get(5, TimeUnit.SECONDS);
        assertFalse(second.isDone(), "the second request got the slot ahead of the first");
        assertEquals(1, UrlConnectionTransport.waiting(host));
        assertEquals(1, UrlConnectionTransport.inFlight(host));

        UrlConnectionTransport.release(host);
        second.get(5, TimeUnit.SECONDS);
        assertEquals(0, UrlConnectionTransport.waiting(host));
        UrlConnectionTransport.release(host);
        assertFalse(UrlConnectionTransport.tracked(host));
    }

    @Test
    void aFreedSlotGoesToTheRequestWaitingNotToANewcomer() throws Exception {
        String host = host();
        OAuthServiceClient.setMaxRequestsPerHost(1);
        take(host, 1000);
        FutureTask<Void> waiting = background(() -> take(host, 20_000));
        eventually(() -> UrlConnectionTransport.waiting(host) == 1, "the request never queued");

        UrlConnectionTransport.release(host);
        assertEquals(1, UrlConnectionTransport.inFlight(host), "the slot wasn't handed to the waiting request");
        assertEquals(0, UrlConnectionTransport.waiting(host));
        assertThrows(RequestNotSentException.class, () -> take(host, 200), "a newcomer took the waiting request's slot");
        waiting.get(5, TimeUnit.SECONDS);

        UrlConnectionTransport.release(host);
        assertFalse(UrlConnectionTransport.tracked(host));
    }

    @Test
    void aRequestThatGivesUpLeavesTheQueue() throws Exception {
        String host = host();
        OAuthServiceClient.setMaxRequestsPerHost(1);
        take(host, 1000);
        FutureTask<Void> patient = background(() -> take(host, 20_000));
        eventually(() -> UrlConnectionTransport.waiting(host) == 1, "the patient request never queued");
        // queued behind the patient one, gives up first
        assertThrows(RequestNotSentException.class, () -> take(host, 150));
        assertEquals(1, UrlConnectionTransport.waiting(host), "the request that gave up is still queued");

        UrlConnectionTransport.release(host);
        patient.get(5, TimeUnit.SECONDS);
        UrlConnectionTransport.release(host);
        assertEquals(0, UrlConnectionTransport.inFlight(host));
        assertFalse(UrlConnectionTransport.tracked(host), "the slot table kept an entry for a host with no requests");
    }

    @Test
    void anInterruptedWaitLeavesNothingBehind() throws Exception {
        String host = host();
        OAuthServiceClient.setMaxRequestsPerHost(1);
        take(host, 1000);
        AtomicReference<Throwable> failure = new AtomicReference<Throwable>();
        Thread waiter = thread(() -> take(host, 20_000), failure);
        eventually(() -> UrlConnectionTransport.waiting(host) == 1, "the request never queued");

        waiter.interrupt();
        waiter.join(5000);
        assertTrue(failure.get() instanceof InterruptedIOException, String.valueOf(failure.get()));
        assertEquals(0, UrlConnectionTransport.waiting(host));
        assertEquals(1, UrlConnectionTransport.inFlight(host), "the interrupted request took a slot");

        UrlConnectionTransport.release(host);
        assertFalse(UrlConnectionTransport.tracked(host));
    }

    @Test
    void aSlotGivenAsTheInterruptComesIsPassedOn() throws Exception {
        String host = host();
        OAuthServiceClient.setMaxRequestsPerHost(1);
        take(host, 1000);
        AtomicReference<Throwable> failure = new AtomicReference<Throwable>();
        Thread interrupted = thread(() -> take(host, 20_000), failure);
        eventually(() -> UrlConnectionTransport.waiting(host) == 1, "the first request never queued");
        FutureTask<Void> next = background(() -> take(host, 20_000));
        eventually(() -> UrlConnectionTransport.waiting(host) == 2, "the second request never queued");

        // the interrupt wakes the first request, which then waits for the lock; the slot is handed to it
        // before it gets the lock, so it holds a slot it will never use
        UrlConnectionTransport.SLOT_LOCK.lock();
        try {
            interrupted.interrupt();
            eventually(() -> UrlConnectionTransport.SLOT_LOCK.hasQueuedThread(interrupted),
                    "the interrupted request never woke");
            UrlConnectionTransport.release(host);
        } finally {
            UrlConnectionTransport.SLOT_LOCK.unlock();
        }
        interrupted.join(5000);
        assertTrue(failure.get() instanceof InterruptedIOException, String.valueOf(failure.get()));

        next.get(5, TimeUnit.SECONDS); // the slot went on to the next request
        assertEquals(1, UrlConnectionTransport.inFlight(host));
        UrlConnectionTransport.release(host);
        assertFalse(UrlConnectionTransport.tracked(host));
    }

    @Test
    void raisingTheLimitLetsWaitingRequestsIn() throws Exception {
        String host = host();
        OAuthServiceClient.setMaxRequestsPerHost(1);
        take(host, 1000);
        FutureTask<Void> a = background(() -> take(host, 20_000));
        FutureTask<Void> b = background(() -> take(host, 20_000));
        eventually(() -> UrlConnectionTransport.waiting(host) == 2, "the requests never queued");

        OAuthServiceClient.setMaxRequestsPerHost(3);
        a.get(5, TimeUnit.SECONDS);
        b.get(5, TimeUnit.SECONDS);
        assertEquals(3, UrlConnectionTransport.inFlight(host));

        for (int i = 0; i < 3; i++) {
            UrlConnectionTransport.release(host);
        }
        assertFalse(UrlConnectionTransport.tracked(host));
    }

    @Test
    void loweringTheLimitKeepsTheRequestsInFlight() throws Exception {
        String host = host();
        OAuthServiceClient.setMaxRequestsPerHost(3);
        take(host, 1000);
        take(host, 1000);
        take(host, 1000);

        OAuthServiceClient.setMaxRequestsPerHost(1);
        assertEquals(3, UrlConnectionTransport.inFlight(host));
        assertThrows(RequestNotSentException.class, () -> take(host, 100));
        UrlConnectionTransport.release(host);
        UrlConnectionTransport.release(host);
        assertThrows(RequestNotSentException.class, () -> take(host, 100), "a request went in at the new limit");
        UrlConnectionTransport.release(host);

        take(host, 1000);
        UrlConnectionTransport.release(host);
        assertFalse(UrlConnectionTransport.tracked(host));
    }

    @Test
    void hostsAreCountedApart() throws Exception {
        String one = host();
        String other = host();
        OAuthServiceClient.setMaxRequestsPerHost(1);
        take(one, 1000);
        take(other, 100);
        assertEquals(1, UrlConnectionTransport.inFlight(one));
        assertEquals(1, UrlConnectionTransport.inFlight(other));
        UrlConnectionTransport.release(one);
        UrlConnectionTransport.release(other);
        assertFalse(UrlConnectionTransport.tracked(one));
        assertFalse(UrlConnectionTransport.tracked(other));
    }

    @Test
    void aRequestToAFullHostFailsAsNotSent() throws Exception {
        // accepts TCP connections and never answers, so a request there holds its slot until its deadline
        final List<Socket> held = Collections.synchronizedList(new ArrayList<Socket>());
        try (final ServerSocket silent = new ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"))) {
            Thread acceptor = new Thread(() -> {
                try {
                    while (true) {
                        held.add(silent.accept());
                    }
                } catch (IOException closed) {
                    // the test is over
                }
            });
            acceptor.setDaemon(true);
            acceptor.start();
            String host = "127.0.0.1:" + silent.getLocalPort();
            String url = "https://" + host + "/x";
            UrlConnectionTransport slow = new UrlConnectionTransport(Duration.ofSeconds(10), Duration.ofSeconds(30),
                    Duration.ofSeconds(3), TestTls.clientTrust());
            UrlConnectionTransport quick = new UrlConnectionTransport(Duration.ofSeconds(10), Duration.ofSeconds(30),
                    Duration.ofMillis(300), TestTls.clientTrust());
            OAuthServiceClient.setMaxRequestsPerHost(1);

            FutureTask<Void> stalled = background(() -> {
                slow.execute(HttpRequest.get(url, Collections.<String, String>emptyMap()));
                return null;
            });
            eventually(() -> UrlConnectionTransport.inFlight(host) == 1, "the stalled request never took its slot");
            eventually(() -> held.size() == 1, "the stalled request never connected");

            RequestNotSentException full = assertThrows(RequestNotSentException.class,
                    () -> quick.execute(HttpRequest.get(url, Collections.<String, String>emptyMap())));
            assertTrue(full.getMessage().contains("Too many requests in flight to " + host), full.getMessage());
            assertEquals(1, held.size(), "the request that found no slot still opened a connection");

            ExecutionException stalledFailure = assertThrows(ExecutionException.class,
                    () -> stalled.get(10, TimeUnit.SECONDS));
            assertTrue(stalledFailure.getCause() instanceof IOException, String.valueOf(stalledFailure.getCause()));
            eventually(() -> UrlConnectionTransport.inFlight(host) == 0, "the stalled request kept its slot");
        } finally {
            for (Socket s : held) {
                s.close();
            }
        }
    }

    /** A host:port no other test uses. */
    private static String host() {
        return "limit-" + HOSTS.incrementAndGet() + ".test:443";
    }

    private static Void take(String host, long timeoutMs) throws IOException {
        UrlConnectionTransport.acquire(host, System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMs), timeoutMs);
        return null;
    }

    private static FutureTask<Void> background(Callable<Void> work) {
        FutureTask<Void> task = new FutureTask<Void>(work);
        Thread t = new Thread(task, "per-host-limit-test");
        t.setDaemon(true);
        t.start();
        return task;
    }

    private static Thread thread(Callable<Void> work, AtomicReference<Throwable> failure) {
        Thread t = new Thread(() -> {
            try {
                work.call();
            } catch (Throwable e) {
                failure.set(e);
            }
        }, "per-host-limit-test");
        t.setDaemon(true);
        t.start();
        return t;
    }

    private static void eventually(BooleanSupplier condition, String what) throws InterruptedException {
        long until = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (!condition.getAsBoolean()) {
            if (System.nanoTime() > until) {
                fail(what);
            }
            Thread.sleep(10);
        }
    }
}
