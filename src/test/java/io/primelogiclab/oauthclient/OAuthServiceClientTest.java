package io.primelogiclab.oauthclient;

import static org.junit.jupiter.api.Assumptions.assumeTrue;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

@Timeout(60)
class OAuthServiceClientTest {

    private static final String JSON = "{\"name\":\"wörd\"}";
    private static final String OWN_TOKEN = "own.token.value";

    private final List<StubServer> servers = new ArrayList<StubServer>();
    private final TokenCache cache = new TokenCache();
    private final CountingFetcher fetcher = new CountingFetcher();

    @AfterEach
    void stopServers() {
        for (StubServer s : servers) {
            s.close();
        }
    }

    // ------------------------------------------------------------------ calls

    @Test
    void shortcutsSendTheMethodBodyContentTypeAndBearerToken() throws Exception {
        StubServer server = server(false);
        server.always("/items", StubServer.json(200, "{}"));
        OAuthServiceClient service = client(info());

        service.get(server.url("/items"));
        service.post(server.url("/items"), JSON);
        service.put(server.url("/items"), JSON);
        service.delete(server.url("/items"));

        List<StubServer.Recorded> r = server.requests();
        assertEquals(Arrays.asList("GET", "POST", "PUT", "DELETE"),
                Arrays.asList(r.get(0).method, r.get(1).method, r.get(2).method, r.get(3).method));
        for (StubServer.Recorded each : r) {
            assertEquals("Bearer tok-1", each.header("Authorization"), each.method);
        }
        assertEquals("", r.get(0).body);
        assertNull(r.get(0).header("Content-Type"));
        assertEquals(JSON, r.get(1).body);
        assertEquals("application/json; charset=UTF-8", r.get(1).header("Content-Type"));
        assertEquals(JSON, r.get(2).body);
        assertEquals("", r.get(3).body);
        assertEquals(1, fetcher.count.get());
    }

    @Test
    void aRequestSendsItsHeadersAndContentType() throws Exception {
        StubServer server = server(false);
        server.always("/items", StubServer.json(201, "{}"));

        ServiceResponse response = client(info()).request(ServiceRequest.put(server.url("/items"), "<a/>")
                .header("Accept", "application/xml").contentType("application/xml").header("X-Trace", "t1"));

        assertEquals(201, response.getStatus());
        StubServer.Recorded r = server.last();
        assertEquals("application/xml", r.header("Accept"));
        assertEquals("application/xml", r.header("Content-Type"));
        assertEquals("t1", r.header("X-Trace"));
        assertEquals("Bearer tok-1", r.header("Authorization"));
    }

    @Test
    void theTokenIsFetchedOnceAndSharedByInstances() throws Exception {
        StubServer server = server(false);
        server.always("/items", StubServer.json(200, "{}"));
        OAuthServiceClient first = client(info());
        OAuthServiceClient second = client(info());

        first.get(server.url("/items"));
        first.get(server.url("/items"));
        first.close();
        second.get(server.url("/items"));

        assertEquals(1, fetcher.count.get());
        assertEquals("Bearer tok-1", server.last().header("Authorization"));
    }

    @Test
    void anOwnTokenIsSentAsIsWithoutClientInfo() throws Exception {
        StubServer server = server(false);
        server.always("/items", StubServer.json(200, "{}"));
        OAuthServiceClient service = client(null);

        service.post(OWN_TOKEN, server.url("/items"), JSON);
        service.get(OWN_TOKEN, server.url("/items"));
        service.put(OWN_TOKEN, server.url("/items"), JSON);
        service.delete(OWN_TOKEN, server.url("/items"));

        for (StubServer.Recorded r : server.requests()) {
            assertEquals("Bearer " + OWN_TOKEN, r.header("Authorization"), r.method);
        }
        assertEquals(0, fetcher.count.get());
    }

    @Test
    void theRequestsScopesReplaceTheDefaults() throws Exception {
        StubServer server = server(false);
        server.always("/items", StubServer.json(200, "{}"));
        OAuthServiceClient service = client(ClientInfo.forTenant("svc", "acme").tokenUrl("https://login.example.com/token")
                .clientId("id").clientSecret("s").scope("default").build());

        service.get(server.url("/items"));
        service.request(ServiceRequest.get(server.url("/items")).scopes("b", "a"));
        service.token("c");

        assertEquals(Arrays.asList(Collections.singletonList("default"), Arrays.asList("b", "a"),
                Collections.singletonList("c")), fetcher.scopes);
        assertEquals("Bearer tok-2", server.last().header("Authorization"));
    }

    @Test
    void tokenGivesTheResponseFields() {
        OAuthServiceClient service = client(info());

        AccessToken token = service.token();

        assertEquals("tok-1", token.getValue());
        assertEquals("https://acme.my.salesforce.com", token.getField("instance_url"));
        assertSame(token, service.token());
    }

    // ------------------------------------------------------------------ answers

    @Test
    void everyStatusComesBackAndRedirectsArentFollowed() throws Exception {
        StubServer server = server(false);
        server.always("/missing", StubServer.json(404, "{\"error\":\"not found\"}"));
        server.always("/broken", new StubServer.Response(500, "text/plain", "boom"));
        server.always("/moved", new StubServer.Response(302, "text/plain", "")
                .header("Location", server.url("/elsewhere")));
        OAuthServiceClient service = client(info());

        ServiceResponse missing = service.get(server.url("/missing"));
        ServiceResponse broken = service.post(server.url("/broken"), JSON);
        ServiceResponse moved = service.get(server.url("/moved"));

        assertEquals(404, missing.getStatus());
        assertFalse(missing.isSuccessful());
        assertEquals("{\"error\":\"not found\"}", missing.getBody());
        assertEquals(500, broken.getStatus());
        assertEquals("boom", broken.getBody());
        assertEquals(302, moved.getStatus());
        assertEquals(server.url("/elsewhere"), moved.getHeader("location"));
        assertEquals(3, server.requests().size());
    }

    @Test
    void aBinaryBodyArrivesIntactAndTextUsesItsCharset() throws Exception {
        byte[] pdf = new byte[256];
        for (int i = 0; i < pdf.length; i++) {
            pdf[i] = (byte) i;
        }
        StubServer server = server(false);
        server.always("/doc", new StubServer.Response(200, "application/pdf", pdf));
        server.always("/latin", new StubServer.Response(200, "text/plain; charset=ISO-8859-1",
                "café".getBytes(StandardCharsets.ISO_8859_1)));
        OAuthServiceClient service = client(info());

        ServiceResponse doc = service.get(server.url("/doc"));
        ServiceResponse latin = service.get(server.url("/latin"));

        assertArrayEquals(pdf, doc.getBodyBytes());
        assertEquals("application/pdf", doc.getHeader("Content-Type"));
        assertEquals("café", latin.getBody());
        assertEquals("ServiceResponse{status=200, contentType=application/pdf, bodyLength=256}", doc.toString());
    }

    @Test
    void aResponseOverTheLimitFails() throws Exception {
        StubServer server = server(false);
        server.always("/big", new StubServer.Response(200, "application/octet-stream", new byte[2048]));
        OAuthServiceClient service = new OAuthServiceClient(cache, fetcher, executor(), 1024);
        service.initialize(info());

        OAuthServiceException e = assertThrows(OAuthServiceException.class, () -> service.get(server.url("/big")));

        assertTrue(e.getMessage().contains("exceeds 1024 bytes"), e.getMessage());
        assertEquals(-1, e.getHttpStatus());
    }

    // ------------------------------------------------------------------ refusals and failures

    @Test
    void aNonHttpsUrlIsRefusedBeforeATokenIsFetched() throws Exception {
        StubServer server = server(false);
        OAuthServiceClient service = client(info());

        assertThrows(IllegalArgumentException.class, () -> service.get("http://localhost:1/items"));
        assertThrows(IllegalArgumentException.class, () -> service.post("ftp://localhost/items", JSON));

        assertEquals(0, fetcher.count.get());
        assertTrue(server.requests().isEmpty());
    }

    @Test
    void aTokenNeverShowsUpInAMessage() {
        OAuthServiceClient service = client(null);

        // token and URL swapped
        IllegalArgumentException swapped = assertThrows(IllegalArgumentException.class,
                () -> service.get("https://api.example.com/items", OWN_TOKEN));
        IllegalArgumentException bad = assertThrows(IllegalArgumentException.class,
                () -> service.get(OWN_TOKEN + "\nX-Evil: 1", "https://api.example.com/items"));

        assertFalse(swapped.getMessage().contains(OWN_TOKEN), swapped.getMessage());
        assertFalse(bad.getMessage().contains(OWN_TOKEN), bad.getMessage());
    }

    @Test
    void aFailedTokenRequestSendsNothing() throws Exception {
        StubServer server = server(false);
        OAuthServiceException failure = new OAuthServiceException("Token request for svc/acme failed: HTTP 401: invalid_client",
                "invalid_client", null, null, 401, null);
        OAuthServiceClient service = new OAuthServiceClient(cache, (info, scopes) -> {
            throw failure;
        }, executor(), OAuthServiceClient.MAX_RESPONSE_BYTES);
        service.initialize(info());

        OAuthServiceException e = assertThrows(OAuthServiceException.class, () -> service.get(server.url("/items")));

        assertSame(failure, e);
        assertTrue(server.requests().isEmpty());
    }

    @Test
    void noAnswerThrowsWithTheUrlRedacted() throws Exception {
        int port;
        try (ServerSocket s = new ServerSocket(0)) {
            port = s.getLocalPort();
        }
        OAuthServiceClient service = client(info());

        OAuthServiceException e = assertThrows(OAuthServiceException.class,
                () -> service.get("https://localhost:" + port + "/items?code=s3cr3t"));

        assertTrue(e.getMessage().contains("GET https://localhost:" + port + "/items?..."), e.getMessage());
        assertFalse(e.getMessage().contains("s3cr3t"), e.getMessage());
        assertFalse(e.getMessage().contains("tok-1"), e.getMessage());
        assertEquals(-1, e.getHttpStatus());
    }

    @Test
    void withoutClientInfoOrAfterCloseCallsAreRefused() throws Exception {
        StubServer server = server(false);
        server.always("/items", StubServer.json(200, "{}"));
        OAuthServiceClient service = client(null);

        assertThrows(IllegalStateException.class, () -> service.get(server.url("/items")));
        assertThrows(IllegalStateException.class, service::token);
        assertThrows(NullPointerException.class, () -> service.initialize(null));

        service.initialize(info());
        service.get(server.url("/items"));
        service.close();
        service.close();

        assertThrows(IllegalStateException.class, () -> service.get(server.url("/items")));
        assertThrows(IllegalStateException.class, () -> service.get(OWN_TOKEN, server.url("/items")));
        assertThrows(IllegalStateException.class, service::token);
        assertThrows(IllegalStateException.class, () -> service.initialize(info()));
        assertEquals(1, server.requests().size());
    }

    @Test
    void theClientCertificateIsPresentedOnServiceCalls() throws Exception {
        StubServer server = server(true);
        server.always("/items", StubServer.json(200, "{}"));
        ClientKey certificate = Fixtures.clientWithChain();
        OAuthServiceClient service = client(ClientInfo.forTenant("svc", "acme").tokenUrl("https://login.example.com/token")
                .clientId("id").clientCertificate(certificate).build());

        assertEquals(200, service.get(server.url("/items")).getStatus());

        assertNotNull(server.last().clientCertificate);
        assertEquals(certificate.getCertificateChain().get(0).getSubjectX500Principal(),
                server.last().clientCertificate.getSubjectX500Principal());
    }

    @Test
    void aPostIsSentAtMostOnceAndOtherMethodsNormally() {
        final List<HttpRequest> sent = new ArrayList<HttpRequest>();
        HttpTransport recording = request -> {
            sent.add(request);
            return new HttpResponse(200, null, "{}");
        };
        OAuthServiceClient service = new OAuthServiceClient(cache, fetcher,
                new HttpExecutor(recording, 0, Duration.ZERO, millis -> { }, null), 4096);
        service.initialize(info());

        service.post("https://api.example.com/items", JSON);
        service.post("https://api.example.com/items", null);
        service.put("https://api.example.com/items", JSON);
        service.get("https://api.example.com/items");
        service.put("https://api.example.com/items", null);

        assertFalse(sent.get(0).isResendable());
        assertFalse(sent.get(1).isResendable());
        assertArrayEquals(new byte[0], sent.get(1).getBody());
        assertTrue(sent.get(2).isResendable());
        assertTrue(sent.get(3).isResendable());
        assertNull(sent.get(3).getBody());
        assertTrue(sent.get(4).isResendable());
        assertArrayEquals(new byte[0], sent.get(4).getBody()); // Content-Length: 0
        for (HttpRequest r : sent) {
            assertEquals(4096, r.getMaxResponseBytes());
            assertNull(r.getClientCertificate());
        }
    }

    // ------------------------------------------------------------------ 401: renew once

    @Test
    void a401RenewsTheTokenOnceAndSendsAgain() throws Exception {
        StubServer server = server(false);
        server.enqueue("/items", StubServer.json(401, "{\"error\":\"invalid_token\"}"));
        server.enqueue("/items", StubServer.json(200, "{\"ok\":true}"));
        OAuthServiceClient service = client(info());

        ServiceResponse response = service.get(server.url("/items"));

        assertEquals(200, response.getStatus());
        List<StubServer.Recorded> r = server.requests();
        assertEquals(2, r.size());
        assertEquals("Bearer tok-1", r.get(0).header("Authorization"));
        assertEquals("Bearer tok-2", r.get(1).header("Authorization"));
        assertEquals(2, fetcher.count.get());
        // the renewed token is the cached one now
        service.get(server.url("/other"));
        assertEquals("Bearer tok-2", server.last().header("Authorization"));
    }

    @Test
    void aPostTurnedAwayWith401IsSentAgainWithItsBody() throws Exception {
        StubServer server = server(false);
        server.enqueue("/items", StubServer.json(401, "{}").header("WWW-Authenticate", "Bearer error=\"invalid_token\""));
        server.enqueue("/items", StubServer.json(201, "{}"));

        ServiceResponse response = client(info()).post(server.url("/items"), JSON);

        assertEquals(201, response.getStatus());
        assertEquals(JSON, server.requests().get(1).body);
        assertEquals("Bearer tok-2", server.requests().get(1).header("Authorization"));
    }

    @Test
    void aSecond401ComesBackWithoutAThirdTry() throws Exception {
        StubServer server = server(false);
        server.always("/items", StubServer.json(401, "{\"error\":\"insufficient\"}"));

        ServiceResponse response = client(info()).get(server.url("/items"));

        assertEquals(401, response.getStatus());
        assertEquals(2, server.requests().size());
        assertEquals(2, fetcher.count.get());
    }

    @Test
    void anOwnTokenTurnedAwayIsNotRenewed() throws Exception {
        StubServer server = server(false);
        server.always("/items", StubServer.json(401, "{}"));

        ServiceResponse response = client(info()).get(OWN_TOKEN, server.url("/items"));

        assertEquals(401, response.getStatus());
        assertEquals(1, server.requests().size());
        assertEquals(0, fetcher.count.get());
    }

    @Test
    void aFailedRenewalThrows() throws Exception {
        StubServer server = server(false);
        server.always("/items", StubServer.json(401, "{}"));
        final AtomicInteger calls = new AtomicInteger();
        OAuthServiceClient service = new OAuthServiceClient(cache, (info, scopes) -> {
            if (calls.incrementAndGet() > 1) {
                throw new OAuthServiceException("Token request for svc/acme failed: HTTP 400: invalid_grant",
                        "invalid_grant", null, null, 400, null);
            }
            return fetcher.fetch(info, scopes);
        }, executor(), OAuthServiceClient.MAX_RESPONSE_BYTES, Duration.ZERO);
        service.initialize(info());

        OAuthServiceException e = assertThrows(OAuthServiceException.class, () -> service.get(server.url("/items")));

        assertEquals("invalid_grant", e.getError());
        assertEquals(1, server.requests().size());
    }

    @Test
    void theResendAfterA401GetsOnlyWhatIsLeftOfTheCall() throws Exception {
        StubServer server = server(false);
        server.enqueue("/slow", StubServer.json(401, "{}").delay(1000));
        server.enqueue("/slow", StubServer.json(200, "{}").delay(1000));
        OAuthServiceClient service = client(info());

        // 1.6 s for the whole call: the first answer takes 1 s, so the resend has about 0.6 s, too little
        assertThrows(OAuthServiceException.class,
                () -> service.request(ServiceRequest.get(server.url("/slow")).timeout(Duration.ofMillis(1600))));
    }

    // ------------------------------------------------------------------ retries

    @Test
    void aBusyAnswerWithRetryAfterIsRetriedAfterThatPause() throws Exception {
        StubServer server = server(false);
        server.enqueue("/items", StubServer.json(429, "{}").header("Retry-After", "2"));
        server.enqueue("/items", StubServer.json(503, "{}").header("Retry-After", "1"));
        server.enqueue("/items", StubServer.json(200, "{}"));

        ServiceResponse response = retryingClient().get(server.url("/items"));

        assertEquals(200, response.getStatus());
        assertEquals(Arrays.asList(2000L, 1000L), sleeps);
        assertEquals(3, server.requests().size());
    }

    @Test
    void withoutRetryAfterOrForA5xxTheAnswerComesBackByDefault() throws Exception {
        StubServer server = server(false);
        server.always("/busy", StubServer.json(429, "{}"));
        server.always("/down", StubServer.json(503, "{}"));
        server.always("/broken", StubServer.json(500, "{}"));
        OAuthServiceClient service = retryingClient();

        assertEquals(429, service.get(server.url("/busy")).getStatus());
        assertEquals(503, service.get(server.url("/down")).getStatus());
        assertEquals(500, service.post(server.url("/broken"), JSON).getStatus());

        assertEquals(3, server.requests().size());
        assertTrue(sleeps.isEmpty());
    }

    @Test
    void aRefusedConnectionIsRetriedThenReported() throws Exception {
        int port;
        try (ServerSocket s = new ServerSocket(0)) {
            port = s.getLocalPort();
        }
        OAuthServiceClient service = retryingClient();

        assertThrows(OAuthServiceException.class, () -> service.get("https://localhost:" + port + "/items"));

        assertEquals(Arrays.asList(500L, 1000L), sleeps);
    }

    @Test
    void retryOnFailureAlsoRetries5xxAndBusyAnswersWithoutRetryAfter() throws Exception {
        StubServer server = server(false);
        server.enqueue("/items", StubServer.json(500, "{}"));
        server.enqueue("/items", StubServer.json(429, "{}"));
        server.enqueue("/items", StubServer.json(200, "{}"));

        ServiceResponse response = retryingClient().request(ServiceRequest.get(server.url("/items")).retryOnFailure());

        assertEquals(200, response.getStatus());
        assertEquals(Arrays.asList(500L, 1000L), sleeps);
    }

    @Test
    void aRetryAfterDateIsReadAgainstTheClock() throws Exception {
        StubServer server = server(false);
        String inThreeSeconds = java.time.format.DateTimeFormatter.RFC_1123_DATE_TIME.format(
                java.time.ZonedDateTime.ofInstant(FIXED.instant().plusSeconds(3), java.time.ZoneOffset.UTC));
        server.enqueue("/items", StubServer.json(503, "{}").header("Retry-After", inThreeSeconds));
        server.enqueue("/items", StubServer.json(200, "{}"));

        assertEquals(200, retryingClient().get(server.url("/items")).getStatus());

        assertEquals(Arrays.asList(3000L), sleeps);
    }

    @Test
    void aPauseThatDoesNotFitTheCallEndsTheRetries() throws Exception {
        StubServer server = server(false);
        server.enqueue("/items", StubServer.json(429, "{}").header("Retry-After", "25"));
        server.enqueue("/items", StubServer.json(200, "{}"));

        // the call has 20 s; a 25 s pause doesn't fit, so the 429 comes back
        assertEquals(429, retryingClient().get(server.url("/items")).getStatus());

        assertTrue(sleeps.isEmpty());
        assertEquals(1, server.requests().size());
    }

    // ------------------------------------------------------------------ settings

    @Test
    void theBuilderChecksEverySettingAtOnce() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> OAuthServiceClient.builder()
                .connectTimeout(Duration.ZERO).readTimeout(null).callTimeout(Duration.ofSeconds(-1))
                .retries(11).maxResponseBytes(10).build());
        String m = e.getMessage();
        for (String part : Arrays.asList("connectTimeout must be positive", "readTimeout must be positive",
                "callTimeout must be positive", "retries must be 0 to 10", "maxResponseBytes must be 1 KB to 256 MB")) {
            assertTrue(m.contains(part), m);
        }
        assertNotNull(OAuthServiceClient.builder().build());
        assertNotNull(OAuthServiceClient.builder().callTimeout(Duration.ofMinutes(5)).retries(0).build());
    }

    @Test
    void aCallsOwnTimeoutEndsASlowCall() throws Exception {
        StubServer server = server(false);
        server.always("/slow", StubServer.json(200, "{}").delay(3000));
        OAuthServiceClient service = client(info());

        long start = System.nanoTime();
        assertThrows(OAuthServiceException.class,
                () -> service.request(ServiceRequest.get(server.url("/slow")).timeout(Duration.ofSeconds(1))));

        assertTrue(System.nanoTime() - start < Duration.ofMillis(2500).toNanos(), "the call ran past its own timeout");
        assertThrows(IllegalArgumentException.class, () -> ServiceRequest.get(server.url("/slow")).timeout(Duration.ZERO));
    }

    // ------------------------------------------------------------------ allowed hosts

    @Test
    void callsGoOnlyToAllowedHosts() throws Exception {
        StubServer server = server(false);
        server.always("/items", StubServer.json(200, "{}"));
        OAuthServiceClient allowed = client(infoBuilder().allowedHost("LOCALHOST").build());
        OAuthServiceClient elsewhere = client(infoBuilder().allowedHost("*.example.com").build());

        assertEquals(200, allowed.get(server.url("/items")).getStatus());
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> elsewhere.get(server.url("/items")));

        assertTrue(e.getMessage().contains("Host localhost isn't an allowed host for svc/acme"), e.getMessage());
        assertEquals(1, server.requests().size());
        assertEquals(1, fetcher.count.get(), "no token fetched for the refused call");
    }

    @Test
    void anOwnTokenCarriesNothingOfTheClientInfo() throws Exception {
        StubServer needsCertificate = server(true);
        needsCertificate.always("/items", StubServer.json(200, "{}"));
        OAuthServiceClient withCertificate = client(ClientInfo.forTenant("svc", "acme").tokenUrl("https://login.example.com/token")
                .clientId("id").clientCertificate(Fixtures.clientWithChain()).allowedHost("*.example.com").build());

        // no client certificate goes with the caller's own token, so a server that needs one refuses the call;
        // and the allowed hosts don't apply, since nothing of the client info is sent
        assertThrows(OAuthServiceException.class, () -> withCertificate.get(OWN_TOKEN, needsCertificate.url("/items")));
        assertTrue(needsCertificate.requests().isEmpty());

        StubServer plain = server(false);
        plain.always("/items", StubServer.json(200, "{}"));
        assertEquals(200, withCertificate.get(OWN_TOKEN, plain.url("/items")).getStatus());
        assertNull(plain.last().clientCertificate);
        assertEquals(0, fetcher.count.get());
    }

    @Test
    void aBrandNewTokenTurnedAwayIsNotRenewed() throws Exception {
        StubServer server = server(false);
        server.always("/items", StubServer.json(401, "{\"error\":\"forbidden\"}"));
        OAuthServiceClient service = new OAuthServiceClient(cache, fetcher, executor(), OAuthServiceClient.MAX_RESPONSE_BYTES);
        service.initialize(info());

        // the token was just issued: a 401 isn't about it (a permission error), so no token request
        assertEquals(401, service.get(server.url("/items")).getStatus());
        assertEquals(401, service.get(server.url("/items")).getStatus());

        assertEquals(1, fetcher.count.get());
        assertEquals(2, server.requests().size());
    }

    @Test
    void aLongOrUnreadableRetryAfterIsNotRetried() throws Exception {
        StubServer server = server(false);
        server.enqueue("/hour", StubServer.json(429, "{}").header("Retry-After", "3600"));
        server.enqueue("/soon", StubServer.json(503, "{}").header("Retry-After", "soon"));
        OAuthServiceClient service = retryingClient();

        // asked for longer than the library waits (30 s): the answer comes back, not an early resend
        // the call has 2 hours, so the hour would fit: still not waited for
        assertEquals(429, service.request(ServiceRequest.get(server.url("/hour")).timeout(Duration.ofHours(2))).getStatus());
        // an unreadable Retry-After isn't the server asking to come back
        assertEquals(503, service.post(server.url("/soon"), JSON).getStatus());

        assertTrue(sleeps.isEmpty());
        assertEquals(2, server.requests().size());
    }

    @Test
    void clientsWithTheSameSettingsShareTheirComponents() {
        OAuthServiceClient a = OAuthServiceClient.builder().callTimeout(Duration.ofSeconds(42)).build();
        OAuthServiceClient b = OAuthServiceClient.builder().callTimeout(Duration.ofSeconds(42)).build();
        OAuthServiceClient c = OAuthServiceClient.builder().callTimeout(Duration.ofSeconds(43)).build();
        assertSame(a.executor(), b.executor());
        assertFalse(a.executor() == c.executor());
        assertSame(new OAuthServiceClient().executor(), OAuthServiceClient.builder().build().executor());
    }

    // ------------------------------------------------------------------ PATCH (Java 11 and later)

    @Test
    void patchSendsTheMethodBodyAndToken() throws Exception {
        assumeTrue(UrlConnectionTransport.patchSupported(), "PATCH needs Java 11");
        StubServer server = server(false);
        server.enqueue("/items/1", StubServer.json(401, "{}"));
        server.enqueue("/items/1", StubServer.json(204, ""));

        ServiceResponse response = client(info()).patch(server.url("/items/1"), JSON);

        assertEquals(204, response.getStatus());
        List<StubServer.Recorded> r = server.requests();
        assertEquals(2, r.size(), "renewed after the 401 and sent again");
        for (StubServer.Recorded each : r) {
            assertEquals("PATCH", each.method);
            assertEquals(JSON, each.body);
            assertEquals("application/json; charset=UTF-8", each.header("Content-Type"));
        }
        assertEquals("Bearer tok-1", r.get(0).header("Authorization"));
        assertEquals("Bearer tok-2", r.get(1).header("Authorization"));
    }

    @Test
    void patchPresentsTheClientCertificateAndFollowsNoRedirect() throws Exception {
        assumeTrue(UrlConnectionTransport.patchSupported(), "PATCH needs Java 11");
        StubServer server = server(true);
        server.always("/items/1", new StubServer.Response(302, "text/plain", "").header("Location", server.url("/elsewhere")));
        ClientKey certificate = Fixtures.clientWithChain();
        OAuthServiceClient service = client(ClientInfo.forTenant("svc", "acme").tokenUrl("https://login.example.com/token")
                .clientId("id").clientCertificate(certificate).build());

        ServiceResponse response = service.patch(server.url("/items/1"), JSON);

        assertEquals(302, response.getStatus());
        assertEquals(1, server.requests().size());
        assertEquals(certificate.getCertificateChain().get(0).getSubjectX500Principal(),
                server.last().clientCertificate.getSubjectX500Principal());
    }

    @Test
    void aPatchEndsAtItsTimeoutAndAtTheSizeLimit() throws Exception {
        assumeTrue(UrlConnectionTransport.patchSupported(), "PATCH needs Java 11");
        StubServer server = server(false);
        server.always("/slow", StubServer.json(200, "{}").delay(3000));
        server.always("/big", new StubServer.Response(200, "application/octet-stream", new byte[2048]));

        long start = System.nanoTime();
        assertThrows(OAuthServiceException.class, () -> client(info())
                .request(ServiceRequest.patch(server.url("/slow"), JSON).timeout(Duration.ofSeconds(1))));
        assertTrue(System.nanoTime() - start < Duration.ofMillis(2500).toNanos(), "the PATCH ran past its timeout");

        OAuthServiceClient small = new OAuthServiceClient(cache, fetcher, executor(), 1024);
        small.initialize(info());
        OAuthServiceException e = assertThrows(OAuthServiceException.class, () -> small.patch(server.url("/big"), JSON));
        assertTrue(e.getMessage().contains("exceeds 1024 bytes"), e.getMessage());
    }

    @Test
    void aPatchIsRefusedWhenAJvmWideSettingWouldBreakTheRules() throws Exception {
        assumeTrue(UrlConnectionTransport.patchSupported(), "PATCH needs Java 11");
        StubServer server = server(false);
        server.always("/items/1", StubServer.json(204, ""));
        OAuthServiceClient service = client(info());

        System.setProperty("jdk.httpclient.enableAllMethodRetry", "true");
        try {
            OAuthServiceException e = assertThrows(OAuthServiceException.class, () -> service.patch(server.url("/items/1"), JSON));
            assertTrue(e.getMessage().contains("enableAllMethodRetry"), e.getMessage());
        } finally {
            System.clearProperty("jdk.httpclient.enableAllMethodRetry");
        }

        java.net.ProxySelector jvmProxies = java.net.ProxySelector.getDefault();
        java.net.ProxySelector.setDefault(new java.net.ProxySelector() {
            @Override
            public List<java.net.Proxy> select(java.net.URI uri) {
                return Collections.singletonList(new java.net.Proxy(java.net.Proxy.Type.SOCKS,
                        new java.net.InetSocketAddress("127.0.0.1", 1080)));
            }

            @Override
            public void connectFailed(java.net.URI uri, java.net.SocketAddress sa, IOException ioe) {
            }
        });
        try {
            OAuthServiceException e = assertThrows(OAuthServiceException.class, () -> service.patch(server.url("/items/1"), JSON));
            assertTrue(e.getMessage().contains("SOCKS"), e.getMessage());
        } finally {
            java.net.ProxySelector.setDefault(jvmProxies);
        }
        assertTrue(server.requests().isEmpty());
        assertEquals(204, service.patch(server.url("/items/1"), JSON).getStatus());
    }

    @Test
    void aPatchHeaderTheJdkRefusesIsReportedWithoutItsValue() throws Exception {
        assumeTrue(UrlConnectionTransport.patchSupported(), "PATCH needs Java 11");
        StubServer server = server(false);
        server.always("/items/1", StubServer.json(204, ""));

        OAuthServiceException e = assertThrows(OAuthServiceException.class, () -> client(info())
                .request(ServiceRequest.patch(server.url("/items/1"), JSON).header("X-Name", "secret\u0100value")));

        assertFalse(e.getMessage().contains("secret"), e.getMessage());
        assertTrue(server.requests().isEmpty());
    }

    @Test
    void aPatchWhoseConnectionIsRefusedIsRetriedThenReported() throws Exception {
        assumeTrue(UrlConnectionTransport.patchSupported(), "PATCH needs Java 11");
        int port;
        try (ServerSocket s = new ServerSocket(0)) {
            port = s.getLocalPort();
        }
        OAuthServiceClient service = retryingClient();

        assertThrows(OAuthServiceException.class, () -> service.patch("https://localhost:" + port + "/items/1", JSON));

        assertEquals(Arrays.asList(500L, 1000L), sleeps);
    }

    // ------------------------------------------------------------------ helpers

    private OAuthServiceClient client(ClientInfo info) {
        OAuthServiceClient service = new OAuthServiceClient(cache, fetcher, executor(), OAuthServiceClient.MAX_RESPONSE_BYTES,
                Duration.ZERO);
        if (info != null) {
            service.initialize(info);
        }
        return service;
    }

    private static final java.time.Clock FIXED = java.time.Clock.fixed(Instant.parse("2026-11-14T10:00:00Z"),
            java.time.ZoneOffset.UTC);
    private final List<Long> sleeps = Collections.synchronizedList(new ArrayList<Long>());

    /** 2 retries with a recording sleeper and a fixed clock; 20 s per call. */
    private OAuthServiceClient retryingClient() {
        UrlConnectionTransport transport = new UrlConnectionTransport(Duration.ofSeconds(5), Duration.ofSeconds(10),
                null, TestTls.clientTrust());
        HttpExecutor http = new HttpExecutor(transport, 2, Duration.ofMillis(500), millis -> sleeps.add(millis),
                Duration.ofSeconds(20), FIXED);
        OAuthServiceClient service = new OAuthServiceClient(cache, fetcher, http, OAuthServiceClient.MAX_RESPONSE_BYTES,
                Duration.ZERO);
        service.initialize(info());
        return service;
    }

    private static HttpExecutor executor() {
        UrlConnectionTransport transport = new UrlConnectionTransport(Duration.ofSeconds(5), Duration.ofSeconds(10),
                Duration.ofSeconds(20), TestTls.clientTrust());
        return new HttpExecutor(transport, 0, Duration.ZERO, HttpExecutor.THREAD_SLEEPER, Duration.ofSeconds(20));
    }

    private static ClientInfo.Builder infoBuilder() {
        return ClientInfo.forTenant("svc", "acme").tokenUrl("https://login.example.com/token").clientId("id").clientSecret("s");
    }

    private static ClientInfo info() {
        return ClientInfo.forTenant("svc", "acme").tokenUrl("https://login.example.com/token")
                .clientId("id").clientSecret("s").build();
    }

    private StubServer server(boolean needClientAuth) throws IOException {
        StubServer s = new StubServer(TestTls.serverContext(), needClientAuth);
        servers.add(s);
        return s;
    }

    /** Hands out tok-1, tok-2, ... and records the scopes asked for. */
    private static final class CountingFetcher implements TokenFetcher {

        final AtomicInteger count = new AtomicInteger();
        final List<List<String>> scopes = Collections.synchronizedList(new ArrayList<List<String>>());

        @Override
        public AccessToken fetch(ClientInfo clientInfo, List<String> requested) {
            scopes.add(requested);
            Map<String, Object> response = new LinkedHashMap<String, Object>();
            response.put("access_token", "tok-" + count.incrementAndGet());
            response.put("token_type", "Bearer");
            response.put("expires_in", 3600);
            response.put("instance_url", "https://acme.my.salesforce.com");
            return AccessToken.fromResponse(response, Instant.now());
        }
    }
}
