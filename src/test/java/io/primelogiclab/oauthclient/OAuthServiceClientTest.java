package io.primelogiclab.oauthclient;

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

    // ------------------------------------------------------------------ helpers

    private OAuthServiceClient client(ClientInfo info) {
        OAuthServiceClient service = new OAuthServiceClient(cache, fetcher, executor(), OAuthServiceClient.MAX_RESPONSE_BYTES);
        if (info != null) {
            service.initialize(info);
        }
        return service;
    }

    private static HttpExecutor executor() {
        UrlConnectionTransport transport = new UrlConnectionTransport(Duration.ofSeconds(5), Duration.ofSeconds(10),
                Duration.ofSeconds(20), TestTls.clientTrust());
        return new HttpExecutor(transport, 0, Duration.ZERO, HttpExecutor.THREAD_SLEEPER, Duration.ofSeconds(20));
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
