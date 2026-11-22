package io.primelogiclab.oauthclient;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.ServerSocket;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

@Timeout(60)
class MetadataCacheTest {

    private static final String OIDC = "/.well-known/openid-configuration";
    private static final String RFC8414 = "/.well-known/oauth-authorization-server";

    private final FakeTime time = new FakeTime();
    private final MetadataCache cache = new MetadataCache(time);
    private final List<StubServer> servers = new ArrayList<StubServer>();
    private final ExecutorService threads = Executors.newCachedThreadPool();

    @AfterEach
    void stop() {
        threads.shutdownNow();
        for (StubServer s : servers) {
            s.close();
        }
    }

    @Test
    void theOpenIdConnectLocationIsReadFirst() throws Exception {
        StubServer server = server();
        String issuer = server.url("/realms/it");
        server.always("/realms/it" + OIDC, document(issuer, server.url("/realms/it/token")));

        ServerMetadata m = cache.resolve(info(issuer), executor());

        assertEquals(server.url("/realms/it/token"), m.tokenEndpoint());
        assertEquals(Arrays.asList("/realms/it" + OIDC), paths(server));
        assertEquals("GET", server.last().method);
        assertEquals("application/json", server.last().header("Accept"));
    }

    @Test
    void thenTheRfc8414LocationAndThenTheAppendedOne() throws Exception {
        StubServer server = server();
        String inserted = server.url("/tenant1");
        server.always(RFC8414 + "/tenant1", document(inserted, server.url("/tenant1/token")));
        assertEquals(server.url("/tenant1/token"), cache.resolve(info(inserted), executor()).tokenEndpoint());
        assertEquals(Arrays.asList("/tenant1" + OIDC, RFC8414 + "/tenant1"), paths(server));

        String appended = server.url("/tenant2");
        server.always("/tenant2" + RFC8414, document(appended, server.url("/tenant2/token")));
        assertEquals(server.url("/tenant2/token"), cache.resolve(info(appended), executor()).tokenEndpoint());
        assertEquals(Arrays.asList("/tenant2" + OIDC, RFC8414 + "/tenant2", "/tenant2" + RFC8414),
                paths(server).subList(2, 5));
    }

    @Test
    void theWellKnownLocationsOfAnIssuerWithoutAPath() {
        assertEquals(Arrays.asList("https://idp.example.com" + OIDC, "https://idp.example.com" + RFC8414),
                MetadataCache.candidateUrls(info("https://idp.example.com/")));
        assertEquals(Arrays.asList("https://idp.example.com/meta.json"),
                MetadataCache.candidateUrls(ClientInfo.global("idp").metadataUrl("https://idp.example.com/meta.json")
                        .clientId("c").clientSecret("s").build()));
    }

    @Test
    void aMetadataUrlIsReadAloneAndChecksTheIssuerWhenOneIsSet() throws Exception {
        StubServer server = server();
        String issuer = server.url("/idp");
        server.always("/custom/meta.json", document(issuer, server.url("/idp/token")));
        ClientInfo.Builder byUrl = ClientInfo.global("idp").metadataUrl(server.url("/custom/meta.json"))
                .clientId("c").clientSecret("s");

        assertEquals(server.url("/idp/token"), cache.resolve(byUrl.build(), executor()).tokenEndpoint());
        assertEquals(Arrays.asList("/custom/meta.json"), paths(server));

        OAuthServiceException e = assertThrows(OAuthServiceException.class,
                () -> cache.resolve(byUrl.issuer(server.url("/other")).build(), executor()));
        assertTrue(e.getMessage().contains("names the issuer " + issuer), e.getMessage());
    }

    @Test
    void anotherIssuerIsRefusedWithAHintForATrailingSlash() throws Exception {
        StubServer server = server();
        String issuer = server.url("/a");
        server.always("/a" + OIDC, document(issuer + "/", server.url("/a/token")));
        OAuthServiceException slash = assertThrows(OAuthServiceException.class, () -> cache.resolve(info(issuer), executor()));
        assertTrue(slash.getMessage().contains("names the issuer " + issuer + "/, not " + issuer), slash.getMessage());
        assertTrue(slash.getMessage().contains("trailing slash included: set the issuer to " + issuer + "/"),
                slash.getMessage());

        String other = server.url("/b");
        server.always("/b" + OIDC, document("https://evil.example.com", server.url("/b/token")));
        OAuthServiceException mismatch = assertThrows(OAuthServiceException.class, () -> cache.resolve(info(other), executor()));
        assertTrue(mismatch.getMessage().contains("names the issuer https://evil.example.com, not " + other),
                mismatch.getMessage());
        assertFalse(mismatch.getMessage().contains("trailing slash"), mismatch.getMessage());
    }

    @Test
    void theTokenEndpointsMustBeHttpsWithoutUserInfo() throws Exception {
        StubServer server = server();
        String http = server.url("/http");
        server.always("/http" + OIDC, document(http, "http://localhost/token"));
        assertMessage(http, "declares a token_endpoint that must be an https URL");

        String none = server.url("/none");
        server.always("/none" + OIDC, StubServer.json(200, "{\"issuer\":\"" + none + "\"}"));
        assertMessage(none, "has no token_endpoint");

        String alias = server.url("/alias");
        server.always("/alias" + OIDC, StubServer.json(200, "{\"issuer\":\"" + alias + "\",\"token_endpoint\":\""
                + server.url("/alias/token") + "\",\"mtls_endpoint_aliases\":{\"token_endpoint\":\"https://u:p@localhost/t\"}}"));
        assertMessage(alias, "declares an mtls_endpoint_aliases.token_endpoint that must not contain user info");
    }

    @Test
    void aDocumentIsKeptForADay() throws Exception {
        StubServer server = server();
        String issuer = server.url("/idp");
        server.always("/idp" + OIDC, document(issuer, server.url("/idp/token")));
        ServerMetadata first = cache.resolve(info(issuer), executor());
        time.advance(MetadataCache.TTL.minusMillis(1));
        assertSame(first, cache.resolve(info(issuer), executor()));
        assertEquals(1, server.requests().size());
        time.advance(Duration.ofMillis(1));
        cache.resolve(info(issuer), executor());
        assertEquals(2, server.requests().size());
    }

    @Test
    void aFailedRefreshKeepsTheDocumentForAnotherDay() throws Exception {
        StubServer server = server();
        String issuer = server.url("/idp");
        server.enqueue("/idp" + OIDC, document(issuer, server.url("/idp/token")));
        server.always("/idp" + OIDC, new StubServer.Response(500, "text/plain", "down"));
        ServerMetadata first = cache.resolve(info(issuer), executor());
        time.advance(MetadataCache.TTL);

        assertSame(first, cache.resolve(info(issuer), executor())); // every location tried, none answered
        assertEquals(4, server.requests().size());
        assertSame(first, cache.resolve(info(issuer), executor()));
        assertEquals(4, server.requests().size());
    }

    @Test
    void withNoDocumentAndNoAnswerTheOtherLocationsArentTried() throws Exception {
        int port;
        try (ServerSocket s = new ServerSocket(0)) {
            port = s.getLocalPort(); // closed again: nothing listens there
        }
        String issuer = "https://localhost:" + port + "/idp";
        OAuthServiceException e = assertThrows(OAuthServiceException.class, () -> cache.resolve(info(issuer), executor()));
        assertTrue(e.getMessage().contains("Couldn't read the authorization server metadata for idp (global)"), e.getMessage());
        assertTrue(e.getMessage().contains(OIDC) && !e.getMessage().contains(RFC8414), e.getMessage());
    }

    @Test
    void aDocumentThatIsntJsonOrTooLargeIsntUsed() throws Exception {
        StubServer server = server();
        String html = server.url("/html");
        server.always("/html" + OIDC, new StubServer.Response(200, "text/html", "<html>sign in</html>"));
        assertMessage(html, "not a JSON object");

        String big = server.url("/big");
        char[] padding = new char[MetadataCache.MAX_DOCUMENT_BYTES];
        Arrays.fill(padding, ' ');
        server.always("/big" + OIDC, StubServer.json(200, "{\"issuer\":\"" + big + "\"," + new String(padding)
                + "\"token_endpoint\":\"" + server.url("/big/token") + "\"}"));
        assertThrows(OAuthServiceException.class, () -> cache.resolve(info(big), executor()));
    }

    @Test
    void threadsReadingAtOnceShareOneRequest() throws Exception {
        StubServer server = server();
        String issuer = server.url("/idp");
        server.always("/idp" + OIDC, document(issuer, server.url("/idp/token")).delay(300));
        List<Future<ServerMetadata>> results = new ArrayList<Future<ServerMetadata>>();
        for (int i = 0; i < 4; i++) {
            results.add(threads.submit(() -> cache.resolve(info(issuer), executor())));
        }
        for (Future<ServerMetadata> r : results) {
            assertEquals(server.url("/idp/token"), r.get(30, TimeUnit.SECONDS).tokenEndpoint());
        }
        assertEquals(1, server.requests().size());
    }

    @Test
    void threadsThatWaitedDontRepeatAFailureThatJustHappened() throws Exception {
        StubServer server = server();
        String issuer = server.url("/idp");
        server.always("/idp" + OIDC, new StubServer.Response(500, "text/plain", "down").delay(300));
        List<Future<ServerMetadata>> results = new ArrayList<Future<ServerMetadata>>();
        for (int i = 0; i < 3; i++) {
            results.add(threads.submit(() -> cache.resolve(info(issuer), executor())));
        }
        for (Future<ServerMetadata> r : results) {
            try {
                r.get(30, TimeUnit.SECONDS);
                throw new AssertionError("expected a failure");
            } catch (java.util.concurrent.ExecutionException e) {
                assertTrue(e.getCause() instanceof OAuthServiceException, String.valueOf(e.getCause()));
            }
        }
        assertEquals(3, server.requests().size()); // one thread's three locations; the others took its failure
    }

    // ------------------------------------------------------------------ helpers

    private void assertMessage(String issuer, String expected) {
        OAuthServiceException e = assertThrows(OAuthServiceException.class, () -> cache.resolve(info(issuer), executor()));
        assertTrue(e.getMessage().contains(expected), e.getMessage());
    }

    static StubServer.Response document(String issuer, String tokenEndpoint) {
        return StubServer.json(200, "{\"issuer\":\"" + issuer + "\",\"token_endpoint\":\"" + tokenEndpoint + "\"}");
    }

    private static ClientInfo info(String issuer) {
        return ClientInfo.global("idp").issuer(issuer).clientId("client").clientSecret("secret").build();
    }

    private static List<String> paths(StubServer server) {
        List<String> out = new ArrayList<String>();
        for (StubServer.Recorded r : server.requests()) {
            out.add(r.path);
        }
        return out;
    }

    private StubServer server() throws IOException {
        StubServer s = new StubServer(TestTls.serverContext(), false);
        servers.add(s);
        return s;
    }

    private static HttpExecutor executor() {
        HttpTransport transport = new UrlConnectionTransport(Duration.ofSeconds(5), Duration.ofSeconds(10),
                Duration.ofSeconds(20), TestTls.clientTrust());
        return new HttpExecutor(transport, TokenClient.MAX_RETRIES, TokenClient.RETRY_BACKOFF, millis -> { },
                Duration.ofSeconds(30));
    }
}
