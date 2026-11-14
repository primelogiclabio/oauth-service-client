package io.primelogiclab.oauthclient;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

@Timeout(30)
class TokenCacheTest {

    private final FakeTime time = new FakeTime();
    private final TokenCache cache = new TokenCache(time, time, Runnable::run, TokenCache.MAXIMUM_SIZE);
    private final ExecutorService threads = Executors.newCachedThreadPool();

    @AfterEach
    void stopThreads() {
        threads.shutdownNow();
    }

    @Test
    void reusesTheTokenUntilTheRenewalMargin() {
        Fetcher fetcher = new Fetcher(3600);
        ClientInfo info = tenant("docusign", "acme");
        assertEquals("t1", cache.get(info, fetcher).getValue());
        time.advance(Duration.ofSeconds(3299));
        assertEquals("t1", cache.get(info, fetcher).getValue());
        assertEquals(1, fetcher.calls.get());
        time.advance(Duration.ofSeconds(1)); // 5 minutes before expiry
        assertEquals("t2", cache.get(info, fetcher).getValue());
        assertEquals("t2", cache.get(info, fetcher).getValue());
        assertEquals(2, fetcher.calls.get());
    }

    @Test
    void shortLivedTokensAreRenewedAtHalfTheirLifetime() {
        Fetcher fetcher = new Fetcher(100);
        ClientInfo info = tenant("docusign", "acme");
        cache.get(info, fetcher);
        time.advance(Duration.ofSeconds(49));
        assertEquals("t1", cache.get(info, fetcher).getValue());
        time.advance(Duration.ofSeconds(1));
        assertEquals("t2", cache.get(info, fetcher).getValue());
    }

    @Test
    void aTokenWithAnUnknownExpiryIsKeptUntilTheServiceRejectsIt() {
        ClientInfo info = global("salesforce");
        AtomicInteger calls = new AtomicInteger();
        TokenFetcher opaque = (i, scopes) -> AccessToken.fromResponse(
                AccessTokenTest.response("access_token", "sf" + calls.incrementAndGet()), time.instant());
        AccessToken first = cache.get(info, opaque);
        time.advance(Duration.ofDays(30));
        assertSame(first, cache.get(info, opaque));
        assertEquals(1, cache.size());
        assertEquals("sf2", cache.renew(info, first, opaque).getValue());
        assertEquals("sf2", cache.get(info, opaque).getValue());
        assertEquals(2, calls.get());
    }

    @Test
    void aTokenWithoutLifetimeIsFetchedEveryTime() {
        Fetcher fetcher = new Fetcher(0);
        ClientInfo info = tenant("docusign", "acme");
        assertEquals("t1", cache.get(info, fetcher).getValue());
        assertEquals("t2", cache.get(info, fetcher).getValue());
    }

    @Test
    void eachServiceAndTenantHasItsOwnToken() {
        Fetcher fetcher = new Fetcher(3600);
        List<ClientInfo> infos = new ArrayList<ClientInfo>();
        infos.add(tenant("docusign", "acme"));
        infos.add(tenant("docusign", "globex"));
        infos.add(tenant("jira", "acme"));
        infos.add(global("docusign"));
        infos.add(tenant("docusign", "GLOBAL")); // a tenant coded GLOBAL is not the global entry
        List<String> first = new ArrayList<String>();
        for (ClientInfo i : infos) {
            first.add(cache.get(i, fetcher).getValue());
        }
        assertEquals(5, fetcher.calls.get());
        assertEquals(5, first.stream().distinct().count());
        for (int n = 0; n < infos.size(); n++) {
            assertEquals(first.get(n), cache.get(infos.get(n), fetcher).getValue());
        }
        assertEquals(5, fetcher.calls.get());
        assertEquals(5, cache.size());
    }

    @Test
    void changedTokenSettingsGetANewTokenButRotatedCredentialsDoNot() {
        Fetcher fetcher = new Fetcher(3600);
        cache.get(tenant("docusign", "acme"), fetcher);
        cache.get(base(ClientInfo.forTenant("docusign", "acme")).clientSecret("rotated").build(), fetcher);
        assertEquals(1, fetcher.calls.get());
        assertEquals("t2", cache.get(base(ClientInfo.forTenant("docusign", "acme")).tokenParameter("audience", "api")
                .build(), fetcher).getValue());
        assertEquals("t3", cache.get(tenant("docusign", "acme"), fetcher).getValue());
        assertEquals(1, cache.size());
    }

    @Test
    void eachScopeSetHasItsOwnToken() {
        Fetcher fetcher = new Fetcher(3600);
        ClientInfo info = tenant("graph", "acme");
        assertEquals("t1", cache.get(info, Arrays.asList("read", "write"), fetcher).getValue());
        assertEquals("t1", cache.get(info, Arrays.asList("write", "read"), fetcher).getValue()); // same set
        assertEquals("t2", cache.get(info, Arrays.asList("admin"), fetcher).getValue());
        assertEquals("t3", cache.get(info, fetcher).getValue()); // no scopes
        assertEquals("t1", cache.get(info, Arrays.asList("read", "write"), fetcher).getValue());
        assertEquals("t2", cache.get(info, Arrays.asList("admin"), fetcher).getValue());
        assertEquals(3, fetcher.calls.get());
        assertEquals(3, cache.size());
        assertEquals(Arrays.asList(Arrays.asList("read", "write"), Arrays.asList("admin"), Collections.<String>emptyList()),
                fetcher.scopesSeen);
    }

    @Test
    void theAppsScopesReplaceTheClientInfoDefaults() {
        Fetcher fetcher = new Fetcher(3600);
        ClientInfo info = base(ClientInfo.forTenant("graph", "acme")).scope("default").build();
        assertEquals("t1", cache.get(info, fetcher).getValue());
        assertEquals("t1", cache.get(info, Arrays.asList(" default "), fetcher).getValue()); // the same scope set
        assertEquals("t2", cache.get(info, Arrays.asList("other", "other"), fetcher).getValue());
        assertEquals(Arrays.asList(Arrays.asList("default"), Arrays.asList("other")), fetcher.scopesSeen);
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> cache.get(info, Arrays.asList("a b"), fetcher));
        assertTrue(e.getMessage().contains("graph/acme"), e.getMessage());
        assertEquals(2, fetcher.calls.get());
    }

    @Test
    void renewForOneScopeSetLeavesTheOthersAlone() {
        Fetcher fetcher = new Fetcher(3600);
        ClientInfo info = tenant("graph", "acme");
        AccessToken read = cache.get(info, Arrays.asList("read"), fetcher);
        AccessToken write = cache.get(info, Arrays.asList("write"), fetcher);
        assertEquals("t3", cache.renew(info, Arrays.asList("read"), read, fetcher).getValue());
        assertSame(write, cache.get(info, Arrays.asList("write"), fetcher));
        assertEquals("t3", cache.get(info, Arrays.asList("read"), fetcher).getValue());
        assertEquals(Arrays.asList("read"), fetcher.scopesSeen.get(2));
    }

    @Test
    void expiredEntriesAreEvicted() {
        Fetcher fetcher = new Fetcher(3600);
        cache.get(tenant("docusign", "acme"), fetcher);
        cache.get(global("salesforce"), new Fetcher(7200));
        time.advance(Duration.ofSeconds(3599));
        assertEquals(2, cache.size());
        // Caffeine's timer wheel evicts in buckets of about a second, so look a little after expiry
        time.advance(Duration.ofSeconds(3));
        assertEquals(1, cache.size());
        time.advance(Duration.ofSeconds(3600));
        assertEquals(0, cache.size());
    }

    @Test
    void concurrentCallersShareOneRequest() throws Exception {
        BlockingFetcher fetcher = new BlockingFetcher(3600);
        ClientInfo info = tenant("docusign", "acme");
        List<Future<AccessToken>> results = new ArrayList<Future<AccessToken>>();
        List<Thread> waiting = new ArrayList<Thread>();
        results.add(threads.submit(() -> cache.get(info, fetcher)));
        fetcher.awaitStarted();
        for (int i = 0; i < 7; i++) {
            ThreadCapture capture = new ThreadCapture();
            results.add(threads.submit(() -> capture.run(() -> cache.get(info, fetcher))));
            waiting.add(capture.thread());
        }
        for (Thread t : waiting) {
            awaitBlocked(t);
        }
        fetcher.release();
        for (Future<AccessToken> r : results) {
            assertEquals("t1", r.get(10, TimeUnit.SECONDS).getValue());
        }
        assertEquals(1, fetcher.calls.get());
    }

    @Test
    void whileOneThreadRenewsOthersGetTheStillValidToken() throws Exception {
        BlockingFetcher fetcher = new BlockingFetcher(3600);
        ClientInfo info = tenant("docusign", "acme");
        fetcher.release();
        AccessToken t1 = cache.get(info, fetcher);
        time.advance(Duration.ofSeconds(3550)); // inside the margin, not expired
        fetcher.block();
        Future<AccessToken> renewing = threads.submit(() -> cache.get(info, fetcher));
        fetcher.awaitStarted();
        assertSame(t1, cache.get(info, fetcher)); // returns at once, no waiting
        fetcher.release();
        assertEquals("t2", renewing.get(10, TimeUnit.SECONDS).getValue());
        assertEquals("t2", cache.get(info, fetcher).getValue());
        assertEquals(2, fetcher.calls.get());
    }

    @Test
    void waitingCallersShareTheFailure() throws Exception {
        BlockingFetcher fetcher = new BlockingFetcher(3600);
        RuntimeException down = new IllegalStateException("token endpoint down");
        fetcher.failWith(down);
        ClientInfo info = tenant("docusign", "acme");
        Future<AccessToken> first = threads.submit(() -> cache.get(info, fetcher));
        fetcher.awaitStarted();
        ThreadCapture capture = new ThreadCapture();
        Future<AccessToken> second = threads.submit(() -> capture.run(() -> cache.get(info, fetcher)));
        awaitBlocked(capture.thread());
        fetcher.release();
        assertSame(down, causeOf(first));
        assertSame(down, causeOf(second));
        assertEquals(1, fetcher.calls.get());

        fetcher.failWith(null); // the next call tries again
        assertEquals("t2", cache.get(info, fetcher).getValue());
    }

    @Test
    void aFailedRenewalKeepsTheValidTokenUntilItExpires() {
        Fetcher fetcher = new Fetcher(3600);
        ClientInfo info = tenant("docusign", "acme");
        AccessToken t1 = cache.get(info, fetcher);
        time.advance(Duration.ofSeconds(3550));
        TokenFetcher failing = (i, scopes) -> {
            throw new IllegalStateException("token endpoint down");
        };
        assertSame(t1, cache.get(info, failing));
        time.advance(Duration.ofSeconds(50));
        assertThrows(IllegalStateException.class, () -> cache.get(info, failing));
    }

    @Test
    void renewReplacesARejectedTokenOnce() {
        Fetcher fetcher = new Fetcher(3600);
        ClientInfo info = tenant("docusign", "acme");
        AccessToken t1 = cache.get(info, fetcher);
        assertEquals("t2", cache.renew(info, t1, fetcher).getValue());
        // a second caller still holding t1 gets the replacement without another request
        assertEquals("t2", cache.renew(info, t1, fetcher).getValue());
        assertEquals("t2", cache.get(info, fetcher).getValue());
        assertEquals(2, fetcher.calls.get());
    }

    @Test
    void renewDropsTheRejectedTokenEvenWhenRenewalFails() {
        Fetcher fetcher = new Fetcher(3600);
        ClientInfo info = tenant("docusign", "acme");
        AccessToken t1 = cache.get(info, fetcher);
        assertThrows(IllegalStateException.class, () -> cache.renew(info, t1, (i, scopes) -> {
            throw new IllegalStateException("token endpoint down");
        }));
        assertEquals("t2", cache.get(info, fetcher).getValue());
    }

    @Test
    void renewGetsANewTokenWhenTheServerReturnsTheSameOne() {
        ClientInfo info = tenant("docusign", "acme");
        AtomicInteger calls = new AtomicInteger();
        TokenFetcher sameEveryTime = (i, scopes) -> {
            calls.incrementAndGet();
            return token("same", 3600);
        };
        AccessToken t = cache.get(info, sameEveryTime);
        assertEquals("same", cache.renew(info, t, sameEveryTime).getValue());
        assertEquals(2, calls.get());
    }

    @Test
    void renewDoesNotSettleForTheRejectedTokenFromARenewalThatStartedEarlier() throws Exception {
        ClientInfo info = tenant("docusign", "acme");
        AccessToken t1 = cache.get(info, new Fetcher(3600));
        time.advance(Duration.ofSeconds(3550)); // inside the margin: the next get renews
        CountDownLatch started = new CountDownLatch(1);
        CountDownLatch gate = new CountDownLatch(1);
        Future<AccessToken> earlier = threads.submit(() -> cache.get(info, (i, scopes) -> {
            started.countDown();
            try {
                assertTrue(gate.await(10, TimeUnit.SECONDS));
            } catch (InterruptedException e) {
                throw new IllegalStateException(e);
            }
            return token(t1.getValue(), 3600); // the server hands out the same token again
        }));
        assertTrue(started.await(10, TimeUnit.SECONDS));
        AtomicInteger calls = new AtomicInteger();
        ThreadCapture capture = new ThreadCapture();
        Future<AccessToken> renewed = threads.submit(() -> capture.run(() -> cache.renew(info, t1, (i, scopes) -> {
            calls.incrementAndGet();
            return token("new", 3600);
        })));
        awaitBlocked(capture.thread());
        gate.countDown();
        assertEquals("t1", earlier.get(10, TimeUnit.SECONDS).getValue());
        assertEquals("new", renewed.get(10, TimeUnit.SECONDS).getValue());
        assertEquals(1, calls.get());
    }

    @Test
    void anInterruptedWaiterGivesUp() throws Exception {
        BlockingFetcher fetcher = new BlockingFetcher(3600);
        ClientInfo info = tenant("docusign", "acme");
        Future<AccessToken> first = threads.submit(() -> cache.get(info, fetcher));
        fetcher.awaitStarted();
        ThreadCapture capture = new ThreadCapture();
        AtomicInteger interruptedAfter = new AtomicInteger();
        Future<AccessToken> second = threads.submit(() -> capture.run(() -> {
            try {
                return cache.get(info, fetcher);
            } finally {
                interruptedAfter.set(Thread.currentThread().isInterrupted() ? 1 : 0);
            }
        }));
        awaitBlocked(capture.thread());
        capture.thread().interrupt();
        Throwable e = causeOf(second);
        assertTrue(e instanceof OAuthServiceException && e.getCause() instanceof InterruptedException, String.valueOf(e));
        assertEquals(1, interruptedAfter.get());
        fetcher.release();
        assertEquals("t1", first.get(10, TimeUnit.SECONDS).getValue());
    }

    @Test
    void whenTheRenewingThreadIsInterruptedTheWaitersTryThemselves() throws Exception {
        BlockingFetcher fetcher = new BlockingFetcher(3600);
        ClientInfo info = tenant("docusign", "acme");
        ThreadCapture renewer = new ThreadCapture();
        Future<AccessToken> first = threads.submit(() -> renewer.run(() -> cache.get(info, fetcher)));
        fetcher.awaitStarted();
        ThreadCapture waiter = new ThreadCapture();
        Future<AccessToken> second = threads.submit(() -> waiter.run(() -> cache.get(info, fetcher)));
        awaitBlocked(waiter.thread());
        fetcher.blockOnlyOnce();
        renewer.thread().interrupt();
        assertTrue(causeOf(first) instanceof IllegalStateException);
        // the interrupted fetch handed out no token, so the waiter's own fetch gives the first one
        assertEquals("t1", second.get(10, TimeUnit.SECONDS).getValue());
        assertEquals(1, fetcher.calls.get());
    }

    @Test
    void aFetcherReturningNullIsAnError() {
        assertThrows(IllegalStateException.class, () -> cache.get(tenant("docusign", "acme"), (i, scopes) -> null));
        assertEquals("t1", cache.get(tenant("docusign", "acme"), new Fetcher(60)).getValue());
    }

    // ------------------------------------------------------------------ helpers

    private static ClientInfo tenant(String service, String tenant) {
        return base(ClientInfo.forTenant(service, tenant)).build();
    }

    private static ClientInfo global(String service) {
        return base(ClientInfo.global(service)).build();
    }

    private static ClientInfo.Builder base(ClientInfo.Builder b) {
        return b.tokenUrl("https://idp.example.com/token").clientId("client").clientSecret("secret");
    }

    private AccessToken token(String value, long lifetimeSeconds) {
        return AccessToken.fromResponse(AccessTokenTest.response("access_token", value, "expires_in", lifetimeSeconds),
                time.instant());
    }

    /** Hands out t1, t2, ... with a fixed lifetime. */
    private class Fetcher implements TokenFetcher {

        final AtomicInteger calls = new AtomicInteger();
        final List<List<String>> scopesSeen = Collections.synchronizedList(new ArrayList<List<String>>());
        private final long lifetime;

        Fetcher(long lifetimeSeconds) {
            this.lifetime = lifetimeSeconds;
        }

        @Override
        public AccessToken fetch(ClientInfo clientInfo, List<String> scopes) {
            scopesSeen.add(scopes);
            return token("t" + calls.incrementAndGet(), lifetime);
        }
    }

    /** A fetcher that waits for the test to release it, then answers or fails. */
    private final class BlockingFetcher extends Fetcher {

        private volatile CountDownLatch started = new CountDownLatch(1);
        private volatile CountDownLatch gate = new CountDownLatch(1);
        private volatile RuntimeException failure;
        private volatile boolean blockOnlyOnce;

        BlockingFetcher(long lifetimeSeconds) {
            super(lifetimeSeconds);
        }

        void block() {
            started = new CountDownLatch(1);
            gate = new CountDownLatch(1);
        }

        void release() {
            gate.countDown();
        }

        void failWith(RuntimeException e) {
            failure = e;
        }

        /** Calls after the current one don't wait. */
        void blockOnlyOnce() {
            blockOnlyOnce = true;
        }

        void awaitStarted() throws InterruptedException {
            assertTrue(started.await(10, TimeUnit.SECONDS), "fetch not started");
        }

        @Override
        public AccessToken fetch(ClientInfo clientInfo, List<String> scopes) {
            CountDownLatch g = gate;
            if (blockOnlyOnce && started.getCount() == 0) {
                g = new CountDownLatch(0);
            }
            started.countDown();
            try {
                if (!g.await(10, TimeUnit.SECONDS)) {
                    throw new IllegalStateException("not released");
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("interrupted", e);
            }
            RuntimeException f = failure;
            if (f != null) {
                calls.incrementAndGet();
                throw f;
            }
            return super.fetch(clientInfo, scopes);
        }
    }

    /** Remembers the pool thread a task runs on, so the test can watch or interrupt it. */
    private static final class ThreadCapture {

        private final CountDownLatch known = new CountDownLatch(1);
        private volatile Thread thread;

        <T> T run(java.util.concurrent.Callable<T> task) throws Exception {
            thread = Thread.currentThread();
            known.countDown();
            return task.call();
        }

        Thread thread() throws InterruptedException {
            assertTrue(known.await(10, TimeUnit.SECONDS), "task not started");
            return thread;
        }
    }

    /** Waits until {@code t} parks, i.e. it waits for the renewal. */
    private static void awaitBlocked(Thread t) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        while (System.nanoTime() < deadline) {
            Thread.State s = t.getState();
            if (s == Thread.State.WAITING || s == Thread.State.TIMED_WAITING) {
                return;
            }
            Thread.sleep(5);
        }
        fail("thread did not block: " + t.getState());
    }

    private static Throwable causeOf(Future<?> f) throws Exception {
        try {
            f.get(10, TimeUnit.SECONDS);
        } catch (ExecutionException e) {
            return e.getCause();
        }
        fail("expected a failure");
        return null;
    }
}
