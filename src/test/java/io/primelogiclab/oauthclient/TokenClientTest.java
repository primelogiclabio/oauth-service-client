package io.primelogiclab.oauthclient;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

@Timeout(60)
class TokenClientTest {

    private static final List<String> NO_SCOPES = Collections.emptyList();
    private static final String SECRET = "p@ss:wörd&more";

    private final FakeTime time = new FakeTime();
    private final List<Long> sleeps = Collections.synchronizedList(new ArrayList<Long>());
    private final List<StubServer> servers = new ArrayList<StubServer>();

    @AfterEach
    void stopServers() {
        for (StubServer s : servers) {
            s.close();
        }
    }

    // ------------------------------------------------------------------ grants and client authentication

    @Test
    void clientCredentialsWithTheSecretInABasicHeader() throws Exception {
        StubServer server = server(false);
        server.enqueue("/token", StubServer.token("tok", 1200));
        ClientInfo info = ClientInfo.forTenant("vertex", "acme").tokenUrl(server.url("/token")).clientId("my client")
                .clientSecret(SECRET).tokenParameter("audience", "verx://migration-api").build();

        AccessToken token = client().fetch(info, Arrays.asList("payroll-calculation"));

        assertEquals("tok", token.getValue());
        assertEquals(FakeTime.START.plusSeconds(1200), token.getExpiresAt());
        StubServer.Recorded r = server.last();
        assertEquals("POST", r.method);
        assertEquals(Arrays.asList("grant_type", "scope", "audience"), new ArrayList<String>(r.form().keySet()));
        assertEquals("client_credentials", r.param("grant_type"));
        assertEquals("payroll-calculation", r.param("scope"));
        assertEquals("verx://migration-api", r.param("audience"));
        // RFC 6749 2.3.1: client ID and secret are form-encoded before Base64
        assertEquals("my+client:p%40ss%3Aw%C3%B6rd%26more", basicCredentials(r));
        assertTrue(r.header("Content-Type").startsWith("application/x-www-form-urlencoded"));
        assertEquals("application/json", r.header("Accept"));
    }

    @Test
    void clientCredentialsWithTheSecretInTheBody() throws Exception {
        StubServer server = server(false);
        server.enqueue("/token", StubServer.token("tok", 3600));
        ClientInfo info = ClientInfo.global("jira").tokenUrl(server.url("/token")).clientId("id").clientSecret(SECRET)
                .clientSecretInBody(true).build();

        client().fetch(info, NO_SCOPES);

        StubServer.Recorded r = server.last();
        assertNull(r.header("Authorization"));
        assertEquals(Arrays.asList("grant_type", "client_id", "client_secret"), new ArrayList<String>(r.form().keySet()));
        assertEquals("id", r.param("client_id"));
        assertEquals(SECRET, r.param("client_secret"));
    }

    @Test
    void privateKeyJwtSendsASignedClientAssertion() throws Exception {
        StubServer server = server(false);
        server.enqueue("/token", StubServer.token("tok", 3600));
        ClientKey key = Fixtures.clientWithChain();
        ClientInfo info = ClientInfo.global("graph").tokenUrl(server.url("/token")).clientId("app-id").signingKey(key).build();

        client().fetch(info, Arrays.asList("https://graph.microsoft.com/.default"));

        StubServer.Recorded r = server.last();
        assertNull(r.header("Authorization"));
        assertEquals("app-id", r.param("client_id"));
        assertEquals(JwtAssertion.CLIENT_ASSERTION_TYPE, r.param("client_assertion_type"));
        TestJwt jwt = TestJwt.parse(r.param("client_assertion"));
        assertEquals(server.url("/token"), jwt.claims.get("aud"));
        assertEquals("app-id", jwt.claims.get("sub"));
        assertTrue(jwt.header.containsKey("x5t#S256"));
        assertTrue(jwt.verifies(key.getCertificateChain().get(0).getPublicKey()));
    }

    @Test
    void jwtBearerWithoutClientAuthenticationSendsOnlyTheGrantAndAssertion() throws Exception {
        StubServer server = server(false);
        server.enqueue("/token", StubServer.token("tok", 3600));
        ClientInfo info = ClientInfo.forTenant("docusign", "acme").tokenUrl(server.url("/token")).grant(Grant.JWT_BEARER)
                .clientId("integration-key").signingKey(Fixtures.rsaKey()).subject("user-guid")
                .assertionAudience("account-d.docusign.com").assertionClaim("scope", "signature impersonation").build();

        client().fetch(info, NO_SCOPES);

        StubServer.Recorded r = server.last();
        assertNull(r.header("Authorization"));
        assertEquals(Arrays.asList("grant_type", "assertion"), new ArrayList<String>(r.form().keySet()));
        assertEquals(Grant.JWT_BEARER.getValue(), r.param("grant_type"));
        TestJwt jwt = TestJwt.parse(r.param("assertion"));
        assertEquals("integration-key", jwt.claims.get("iss"));
        assertEquals("user-guid", jwt.claims.get("sub"));
        assertEquals("signature impersonation", jwt.claims.get("scope"));
    }

    @Test
    void jwtBearerWithASecretAuthenticatesTheClientToo() throws Exception {
        StubServer server = server(false);
        server.enqueue("/token", StubServer.token("tok", 3600));
        ClientInfo info = ClientInfo.global("oic").tokenUrl(server.url("/token")).grant(Grant.JWT_BEARER).clientId("app")
                .clientSecret("s").signingKey(Fixtures.rsaKey()).subject("integration.user")
                .assertionAudience("https://identity.oraclecloud.com/").build();

        client().fetch(info, Arrays.asList("urn:opc:resource:consumer::all"));

        StubServer.Recorded r = server.last();
        assertEquals("app:s", basicCredentials(r));
        assertEquals(Arrays.asList("grant_type", "assertion", "scope"), new ArrayList<String>(r.form().keySet()));
    }

    @Test
    void refreshTokenGrant() throws Exception {
        StubServer server = server(false);
        server.enqueue("/token", StubServer.token("tok", 3600));
        ClientInfo info = ClientInfo.forTenant("jira", "acme").tokenUrl(server.url("/token")).grant(Grant.REFRESH_TOKEN)
                .clientId("id").clientSecret("s").clientSecretInBody(true).refreshToken("rt-1").subject("user-1").build();

        client().fetch(info, NO_SCOPES);

        Map<String, String> form = server.last().form();
        assertEquals("refresh_token", form.get("grant_type"));
        assertEquals("rt-1", form.get("refresh_token"));
        assertEquals("id", form.get("client_id"));
        assertEquals("s", form.get("client_secret"));
    }

    @Test
    void theClientCertificateIsPresentedForMutualTls() throws Exception {
        StubServer server = server(true);
        server.always("/token", StubServer.token("tok", 3600));
        ClientInfo certificateOnly = ClientInfo.global("bank").tokenUrl(server.url("/token")).clientId("id")
                .clientCertificate(Fixtures.clientWithChain()).build();

        client().fetch(certificateOnly, NO_SCOPES);
        StubServer.Recorded r = server.last();
        assertTrue(r.clientCertificate.getSubjectX500Principal().getName().contains("CN=test-client"));
        assertEquals("id", r.param("client_id"));
        assertNull(r.header("Authorization"));

        ClientInfo withSecret = ClientInfo.global("bank").tokenUrl(server.url("/token")).clientId("id").clientSecret("s")
                .clientCertificate(Fixtures.clientWithChain()).build();
        client().fetch(withSecret, NO_SCOPES);
        assertTrue(server.last().clientCertificate != null);
        assertEquals("id:s", basicCredentials(server.last()));
    }

    @Test
    void withoutAClientCertificateAServerThatNeedsOneRefusesTheHandshake() throws Exception {
        StubServer server = server(true);
        server.always("/token", StubServer.token("tok", 3600));
        ClientInfo info = ClientInfo.global("bank").tokenUrl(server.url("/token")).clientId("id").clientSecret("s").build();

        // TLS 1.2 fails in the handshake; with TLS 1.3 the server's refusal arrives after it, as a write
        // error on a request already sent: neither is retried
        assertThrows(OAuthServiceException.class, () -> client().fetch(info, NO_SCOPES));
        assertTrue(server.requests().isEmpty());
        assertEquals(Collections.emptyList(), sleeps, "a refused client certificate isn't retried");
    }

    @Test
    void anUntrustedServerCertificateFailsAtOnce() throws Exception {
        StubServer server = server(false);
        server.always("/token", StubServer.token("tok", 3600));
        ClientInfo info = ClientInfo.global("api").tokenUrl(server.url("/token")).clientId("id").clientSecret("s").build();
        HttpTransport jvmTrust = new UrlConnectionTransport(Duration.ofSeconds(5), Duration.ofSeconds(10),
                Duration.ofSeconds(20), null); // the test CA isn't in the JVM's trust store
        TokenClient client = new TokenClient(new HttpExecutor(jvmTrust, TokenClient.MAX_RETRIES, TokenClient.RETRY_BACKOFF,
                millis -> sleeps.add(millis), Duration.ofSeconds(30)), time);

        OAuthServiceException e = assertThrows(OAuthServiceException.class, () -> client.fetch(info, NO_SCOPES));

        assertTrue(HttpExecutor.tlsHandshakeFailed(e), String.valueOf(e.getCause()));
        assertEquals(Collections.emptyList(), sleeps, "a failed handshake isn't retried");
        assertTrue(server.requests().isEmpty());
    }

    // ------------------------------------------------------------------ scopes

    @Test
    void scopesAreSentJoinedBySpacesAndLeftOutWhenThereAreNone() throws Exception {
        StubServer server = server(false);
        server.always("/token", StubServer.token("tok", 3600));
        ClientInfo info = ClientInfo.global("api").tokenUrl(server.url("/token")).clientId("id").clientSecret("s").build();

        client().fetch(info, Arrays.asList("read", "write"));
        assertEquals("read write", server.last().param("scope"));
        client().fetch(info, NO_SCOPES);
        assertFalse(server.last().form().containsKey("scope"));
    }

    @Test
    void throughTheCacheTheAppsScopesWinOverTheDefaults() throws Exception {
        StubServer server = server(false);
        server.always("/token", StubServer.token("tok", 3600));
        ClientInfo info = ClientInfo.global("api").tokenUrl(server.url("/token")).clientId("id").clientSecret("s")
                .scope("default").build();
        TokenCache cache = new TokenCache(time, time, Runnable::run, TokenCache.MAXIMUM_SIZE);
        TokenClient client = client();

        cache.get(info, client);
        assertEquals("default", server.last().param("scope"));
        cache.get(info, Arrays.asList("app.read"), client);
        assertEquals("app.read", server.last().param("scope"));
        assertEquals(2, server.requests().size());
    }

    // ------------------------------------------------------------------ failures and retries

    @Test
    void anOAuthErrorKeepsItsFieldsAndIsNotRetried() throws Exception {
        StubServer server = server(false);
        server.always("/token", StubServer.json(400,
                "{\"error\":\"invalid_grant\",\"error_description\":\"consent required\",\"error_uri\":\"https://docs\"}"));
        ClientInfo info = ClientInfo.forTenant("docusign", "acme").tokenUrl(server.url("/token")).clientId("id")
                .clientSecret(SECRET).build();

        OAuthServiceException e = assertThrows(OAuthServiceException.class, () -> client().fetch(info, NO_SCOPES));

        assertEquals("invalid_grant", e.getError());
        assertEquals("consent required", e.getErrorDescription());
        assertEquals("https://docs", e.getErrorUri());
        assertEquals(400, e.getHttpStatus());
        assertTrue(e.getMessage().contains("docusign/acme"), e.getMessage());
        assertTrue(e.getMessage().contains("HTTP 400: invalid_grant - consent required"), e.getMessage());
        assertFalse(e.getMessage().contains("p@ss"), "no secret in the message");
        assertEquals(1, server.requests().size());
    }

    @Test
    void aNonOAuthErrorBodyIsCutAndCleanedAndA502IsNotRetried() throws Exception {
        StubServer server = server(false);
        StringBuilder page = new StringBuilder("<html>\nforged\rline ");
        while (page.length() < 800) {
            page.append("x");
        }
        server.always("/token", new StubServer.Response(502, "text/html", page.toString()));
        ClientInfo info = ClientInfo.global("api").tokenUrl(server.url("/token")).clientId("id").clientSecret("s").build();

        OAuthServiceException e = assertThrows(OAuthServiceException.class, () -> client().fetch(info, NO_SCOPES));

        assertNull(e.getError());
        assertEquals(502, e.getHttpStatus());
        assertFalse(e.getMessage().contains("\n") || e.getMessage().contains("\r"), e.getMessage());
        assertTrue(e.getMessage().endsWith("..."), e.getMessage());
        assertEquals(1, server.requests().size());
    }

    @Test
    void a429WithRetryAfterIsRetriedWithAFreshAssertion() throws Exception {
        StubServer server = server(false);
        server.enqueue("/token", StubServer.json(429, "{}").header("Retry-After", "2"));
        server.enqueue("/token", StubServer.token("tok", 3600));
        ClientInfo info = ClientInfo.global("okta").tokenUrl(server.url("/token")).clientId("app")
                .signingKey(Fixtures.rsaKey()).build();

        assertEquals("tok", client().fetch(info, NO_SCOPES).getValue());

        assertEquals(Arrays.asList(2000L), sleeps);
        List<StubServer.Recorded> r = server.requests();
        assertEquals(2, r.size());
        assertNotEquals(TestJwt.parse(r.get(0).param("client_assertion")).claims.get("jti"),
                TestJwt.parse(r.get(1).param("client_assertion")).claims.get("jti"));
    }

    @Test
    void a503WithRetryAfterIsRetriedButAPlain500Or503IsNot() throws Exception {
        StubServer server = server(false);
        server.enqueue("/token", StubServer.json(503, "{}").header("Retry-After", "1"));
        server.enqueue("/token", StubServer.token("tok", 3600));
        ClientInfo info = ClientInfo.global("api").tokenUrl(server.url("/token")).clientId("id").clientSecret("s").build();
        assertEquals("tok", client().fetch(info, NO_SCOPES).getValue());
        assertEquals(2, server.requests().size());

        server.enqueue("/token", StubServer.json(500, "{}"));
        assertThrows(OAuthServiceException.class, () -> client().fetch(info, NO_SCOPES));
        server.enqueue("/token", StubServer.json(503, "{}"));
        assertThrows(OAuthServiceException.class, () -> client().fetch(info, NO_SCOPES));
        assertEquals(4, server.requests().size());
    }

    @Test
    void aRefusedConnectionIsRetriedThenReported() throws Exception {
        int port;
        try (ServerSocket s = new ServerSocket(0)) {
            port = s.getLocalPort(); // closed again: nothing listens there
        }
        ClientInfo info = ClientInfo.forTenant("api", "acme").tokenUrl("https://localhost:" + port + "/token")
                .clientId("id").clientSecret("s").build();

        OAuthServiceException e = assertThrows(OAuthServiceException.class, () -> client().fetch(info, NO_SCOPES));

        assertEquals(Arrays.asList(500L, 1000L), sleeps); // 3 attempts
        assertEquals(-1, e.getHttpStatus());
        assertTrue(e.getMessage().startsWith("Token request for api/acme failed: "), e.getMessage());
    }

    @Test
    void anAnswerThatIsNotAUsableTokenIsRejected() throws Exception {
        StubServer server = server(false);
        ClientInfo info = ClientInfo.global("api").tokenUrl(server.url("/token")).clientId("id").clientSecret("s").build();

        server.enqueue("/token", StubServer.json(200, "{\"access_token\":\"two words\"}"));
        assertEquals("invalid_response", assertThrows(OAuthServiceException.class, () -> client().fetch(info, NO_SCOPES)).getError());
        server.enqueue("/token", StubServer.json(200, "{\"token_type\":\"Bearer\"}"));
        assertEquals("invalid_response", assertThrows(OAuthServiceException.class, () -> client().fetch(info, NO_SCOPES)).getError());
        StringBuilder huge = new StringBuilder("{\"access_token\":\"");
        while (huge.length() < TokenClient.MAX_RESPONSE_CHARS + 10) {
            huge.append('a');
        }
        server.enqueue("/token", StubServer.json(200, huge.append("\"}").toString()));
        assertEquals("invalid_response", assertThrows(OAuthServiceException.class, () -> client().fetch(info, NO_SCOPES)).getError());
    }

    @Test
    void aFormEncodedTokenAnswerIsRead() throws Exception {
        StubServer server = server(false);
        server.enqueue("/token", new StubServer.Response(200, "application/x-www-form-urlencoded",
                "access_token=tok&token_type=bearer&expires_in=60"));
        ClientInfo info = ClientInfo.global("old").tokenUrl(server.url("/token")).clientId("id").clientSecret("s").build();
        AccessToken token = client().fetch(info, NO_SCOPES);
        assertEquals("Bearer tok", token.toAuthorizationHeader());
        assertEquals(FakeTime.START.plusSeconds(60), token.getExpiresAt());
    }

    @Test
    void aPlainHttpUrlIsRefusedBeforeAnythingIsSent() throws Exception {
        StubServer server = server(false);
        final String http = server.url("/token").replace("https:", "http:");
        HttpExecutor executor = executor();
        OAuthServiceException e = assertThrows(OAuthServiceException.class, () -> executor.execute(new Supplier<HttpRequest>() {
            @Override
            public HttpRequest get() {
                return HttpRequest.post(http, Collections.<String, String>emptyMap(), "a=b");
            }
        }, HttpExecutor.Retry.ALWAYS));
        assertTrue(e.getMessage().contains("must be an https URL"), e.getMessage());
        assertTrue(server.requests().isEmpty());
    }

    @Test
    void everyTokenRequestIsSentNotResendableWithALimitedAnswer() {
        final List<HttpRequest> sent = new ArrayList<HttpRequest>();
        HttpTransport recording = request -> {
            sent.add(request);
            return new HttpResponse(200, null, "{\"access_token\":\"tok\",\"expires_in\":3600}");
        };
        TokenClient client = new TokenClient(new HttpExecutor(recording, 0, Duration.ZERO, millis -> { }, null), time);

        client.fetch(ClientInfo.global("svc").tokenUrl("https://idp.example.com/token").clientId("id").clientSecret(SECRET)
                .build(), NO_SCOPES);
        client.fetch(ClientInfo.global("okta").tokenUrl("https://idp.example.com/token").clientId("id")
                .signingKey(Fixtures.rsaKey()).build(), NO_SCOPES);
        client.fetch(ClientInfo.global("docusign").tokenUrl("https://idp.example.com/token").grant(Grant.JWT_BEARER)
                .clientId("id").signingKey(Fixtures.rsaKey()).subject("u").assertionAudience("aud").build(), NO_SCOPES);

        assertEquals(3, sent.size());
        for (HttpRequest r : sent) {
            assertFalse(r.isResendable(), r.toString());
            assertEquals(TokenClient.MAX_RESPONSE_BYTES, r.getMaxResponseBytes());
        }
    }

    @Test
    void credentialsTheServerEchoesAreRemovedFromTheError() throws Exception {
        String refreshToken = "rt-0123456789-secret";
        StubServer server = server(false);
        server.enqueue("/token", StubServer.json(400, "{\"error\":\"invalid_grant\",\"error_description\":\"refresh token "
                + refreshToken + " is revoked\"}"));
        server.enqueue("/token", new StubServer.Response(502, "text/plain", "echo: client_secret="
                + TokenClient.formEncode(SECRET) + "&refresh_token=" + refreshToken));
        ClientInfo info = ClientInfo.forTenant("jira", "acme").tokenUrl(server.url("/token")).grant(Grant.REFRESH_TOKEN)
                .clientId("id").clientSecret(SECRET).clientSecretInBody(true).refreshToken(refreshToken).subject("u").build();

        OAuthServiceException oauth = assertThrows(OAuthServiceException.class, () -> client().fetch(info, NO_SCOPES));
        OAuthServiceException echo = assertThrows(OAuthServiceException.class, () -> client().fetch(info, NO_SCOPES));

        assertEquals("refresh token **** is revoked", oauth.getErrorDescription());
        assertFalse(oauth.getMessage().contains(refreshToken), oauth.getMessage());
        assertFalse(echo.getMessage().contains(refreshToken), echo.getMessage());
        assertFalse(echo.getMessage().contains(TokenClient.formEncode(SECRET)), echo.getMessage());
        assertTrue(echo.getMessage().contains("client_secret=****"), echo.getMessage());
    }

    @Test
    void aHugeRetryAfterIsNotTakenAsRetryAtOnce() throws Exception {
        StubServer server = server(false);
        // times 1000 this wraps around to -616 ms, which would mean "retry at once"
        server.enqueue("/token", StubServer.json(429, "{}").header("Retry-After", "18446744073709551"));
        server.enqueue("/token", StubServer.token("tok", 3600));
        ClientInfo info = ClientInfo.global("svc").tokenUrl(server.url("/token")).clientId("id").clientSecret(SECRET).build();

        // capped at 30 s, which doesn't fit in this client's 30 s call: the 429 is reported, not retried at once
        OAuthServiceException e = assertThrows(OAuthServiceException.class, () -> client().fetch(info, NO_SCOPES));

        assertEquals(429, e.getHttpStatus());
        assertEquals(1, server.requests().size());
        assertTrue(sleeps.isEmpty());
    }

    @Test
    void aRetryAfterTooLongToWaitForIsHandedToTheCache() throws Exception {
        StubServer server = server(false);
        ClientInfo info = ClientInfo.global("vertex").tokenUrl(server.url("/token")).clientId("id").clientSecret(SECRET).build();

        // over the 30 s a call may pause for: reported, with the pause for the token cache to honor
        server.enqueue("/token", StubServer.json(429, "{\"error\":\"too_many_requests\"}").header("Retry-After", "120"));
        OAuthServiceException seconds = assertThrows(OAuthServiceException.class, () -> client().fetch(info, NO_SCOPES));
        assertEquals(429, seconds.getHttpStatus());
        assertEquals(Duration.ofSeconds(120), seconds.retryAfter());

        // a date, counted from the token client's clock, and no more than the 24 hours a wait may last
        server.enqueue("/token", StubServer.json(503, "{}").header("Retry-After", "Fri, 01 Jan 2100 00:00:00 GMT"));
        OAuthServiceException date = assertThrows(OAuthServiceException.class, () -> client().fetch(info, NO_SCOPES));
        assertEquals(Duration.ofHours(24), date.retryAfter());

        // only a busy server asks to come back
        server.enqueue("/token", StubServer.json(400, "{\"error\":\"invalid_client\"}").header("Retry-After", "120"));
        assertNull(assertThrows(OAuthServiceException.class, () -> client().fetch(info, NO_SCOPES)).retryAfter());
        // and in a form that can be read (a 503 without one isn't resent, unlike a 429)
        server.enqueue("/token", StubServer.json(503, "{}").header("Retry-After", "soon"));
        assertNull(assertThrows(OAuthServiceException.class, () -> client().fetch(info, NO_SCOPES)).retryAfter());
        assertEquals(4, server.requests().size());
    }

    // ------------------------------------------------------------------ the token endpoint from server metadata

    @Test
    void theTokenEndpointComesFromTheServersMetadataReadOnce() throws Exception {
        StubServer server = server(false);
        String issuer = server.url("/idp");
        server.always("/idp/.well-known/openid-configuration", MetadataCacheTest.document(issuer, server.url("/idp/token")));
        server.always("/idp/token", StubServer.token("tok", 3600));
        ClientInfo info = ClientInfo.global("okta").issuer(issuer).clientId("app").signingKey(Fixtures.rsaKey()).build();

        assertEquals("tok", client().fetch(info, NO_SCOPES).getValue());
        client().fetch(info, NO_SCOPES);

        assertEquals(Arrays.asList("/idp/.well-known/openid-configuration", "/idp/token", "/idp/token"), paths(server));
        // a client assertion's audience is the endpoint it goes to
        assertEquals(server.url("/idp/token"), TestJwt.parse(server.last().param("client_assertion")).claims.get("aud"));
    }

    @Test
    void aClientWithACertificateUsesTheMutualTlsAlias() throws Exception {
        StubServer meta = server(false);
        StubServer mtls = server(true);
        String issuer = meta.url("/idp");
        meta.always("/idp/.well-known/openid-configuration", StubServer.json(200, "{\"issuer\":\"" + issuer
                + "\",\"token_endpoint\":\"" + meta.url("/idp/token") + "\",\"mtls_endpoint_aliases\":{\"token_endpoint\":\""
                + mtls.url("/idp/mtls/token") + "\"}}"));
        mtls.always("/idp/mtls/token", StubServer.token("bound", 3600));
        ClientInfo info = ClientInfo.global("auth0").issuer(issuer).clientId("app")
                .clientCertificate(Fixtures.clientWithChain()).build();

        assertEquals("bound", client().fetch(info, NO_SCOPES).getValue());

        assertEquals(Arrays.asList("/idp/mtls/token"), paths(mtls));
        assertEquals("app", mtls.last().param("client_id"));
        assertEquals(Arrays.asList("/idp/.well-known/openid-configuration"), paths(meta)); // nothing else goes there

        // a client without a certificate stays on the plain endpoint
        meta.always("/idp/token", StubServer.token("plain", 3600));
        assertEquals("plain", client().fetch(ClientInfo.global("auth0").issuer(issuer).clientId("app")
                .clientSecret(SECRET).build(), NO_SCOPES).getValue());
    }

    @Test
    void theSecretGoesWhereTheServerSaysItTakesIt() throws Exception {
        StubServer server = server(false);
        String postOnly = server.url("/post");
        server.always("/post/.well-known/openid-configuration", StubServer.json(200, "{\"issuer\":\"" + postOnly
                + "\",\"token_endpoint\":\"" + server.url("/post/token")
                + "\",\"token_endpoint_auth_methods_supported\":[\"client_secret_post\",\"private_key_jwt\"]}"));
        server.always("/post/token", StubServer.token("tok", 3600));
        client().fetch(ClientInfo.global("svc").issuer(postOnly).clientId("id").clientSecret(SECRET).build(), NO_SCOPES);
        assertEquals(SECRET, server.last().param("client_secret"));
        assertEquals(null, server.last().header("Authorization"));

        String basicOnly = server.url("/basic");
        server.always("/basic/.well-known/openid-configuration", StubServer.json(200, "{\"issuer\":\"" + basicOnly
                + "\",\"token_endpoint\":\"" + server.url("/basic/token")
                + "\",\"token_endpoint_auth_methods_supported\":[\"client_secret_basic\"]}"));
        server.always("/basic/token", StubServer.token("tok", 3600));
        client().fetch(ClientInfo.global("svc").issuer(basicOnly).clientId("id").clientSecret(SECRET)
                .clientSecretInBody(true).build(), NO_SCOPES);
        assertTrue(basicCredentials(server.last()).endsWith(":" + TokenClient.formEncode(SECRET)));
        assertNull(server.last().param("client_secret"));
    }

    @Test
    void onlyTheTwoSecretMethodsAreAdaptedToWhatTheServerLists() {
        List<String> postOnly = Arrays.asList("client_secret_post");
        assertEquals(ClientInfo.ClientAuthentication.CLIENT_SECRET_POST,
                TokenClient.listedAuthentication(ClientInfo.ClientAuthentication.CLIENT_SECRET_BASIC, postOnly));
        // a server that lists nothing gets what is configured, as does one that lists neither secret method
        assertEquals(ClientInfo.ClientAuthentication.CLIENT_SECRET_BASIC, TokenClient.listedAuthentication(
                ClientInfo.ClientAuthentication.CLIENT_SECRET_BASIC, Collections.<String>emptyList()));
        assertEquals(ClientInfo.ClientAuthentication.CLIENT_SECRET_BASIC, TokenClient.listedAuthentication(
                ClientInfo.ClientAuthentication.CLIENT_SECRET_BASIC, Arrays.asList("private_key_jwt")));
        for (ClientInfo.ClientAuthentication other : Arrays.asList(ClientInfo.ClientAuthentication.PRIVATE_KEY_JWT,
                ClientInfo.ClientAuthentication.MUTUAL_TLS, ClientInfo.ClientAuthentication.NONE)) {
            assertEquals(other, TokenClient.listedAuthentication(other, postOnly));
        }
    }

    @Test
    void aTokenUrlNeverReadsMetadata() throws Exception {
        StubServer server = server(false);
        server.always("/token", StubServer.token("tok", 3600));
        client().fetch(ClientInfo.global("svc").tokenUrl(server.url("/token")).clientId("id").clientSecret(SECRET).build(),
                NO_SCOPES);
        assertEquals(Arrays.asList("/token"), paths(server));
    }

    @Test
    void aMetadataFailureIsAFailedTokenRequest() throws Exception {
        StubServer server = server(false); // nothing at the well-known locations
        OAuthServiceException e = assertThrows(OAuthServiceException.class, () -> client().fetch(ClientInfo.global("svc")
                .issuer(server.url("/idp")).clientId("id").clientSecret(SECRET).build(), NO_SCOPES));
        assertTrue(e.getMessage().startsWith("Token request for svc (global) failed: Couldn't read the authorization "
                + "server metadata"), e.getMessage());
        assertEquals(3, server.requests().size());
    }

    @Test
    void debugLogsGetOnlyTheRequestsDescription() throws Exception {
        final List<Object> parameters = Collections.synchronizedList(new ArrayList<Object>());
        java.util.logging.Logger log = java.util.logging.Logger.getLogger(HttpExecutor.class.getName());
        java.util.logging.Level level = log.getLevel();
        java.util.logging.Handler handler = new java.util.logging.Handler() {
            @Override
            public void publish(java.util.logging.LogRecord record) {
                if (record.getParameters() != null) {
                    parameters.addAll(Arrays.asList(record.getParameters()));
                }
            }

            @Override
            public void flush() {
            }

            @Override
            public void close() {
            }
        };
        log.addHandler(handler);
        log.setLevel(java.util.logging.Level.FINE);
        try {
            StubServer server = server(false);
            server.enqueue("/token", StubServer.json(429, "{}").header("Retry-After", "1"));
            server.enqueue("/token", StubServer.token("tok", 3600));
            client().fetch(ClientInfo.global("svc").tokenUrl(server.url("/token")).clientId("id").clientSecret(SECRET)
                    .build(), NO_SCOPES);
        } finally {
            log.removeHandler(handler);
            log.setLevel(level);
        }
        assertFalse(parameters.isEmpty());
        for (Object p : parameters) {
            assertFalse(p instanceof HttpRequest, "a request object was handed to the log");
        }
    }

    // ------------------------------------------------------------------ helpers

    private StubServer server(boolean needClientAuth) throws IOException {
        StubServer s = new StubServer(TestTls.serverContext(), needClientAuth);
        servers.add(s);
        return s;
    }

    private HttpExecutor executor() {
        HttpTransport transport = new UrlConnectionTransport(Duration.ofSeconds(5), Duration.ofSeconds(10),
                Duration.ofSeconds(20), TestTls.clientTrust());
        return new HttpExecutor(transport, TokenClient.MAX_RETRIES, TokenClient.RETRY_BACKOFF,
                millis -> sleeps.add(millis), Duration.ofSeconds(30));
    }

    private TokenClient client() {
        return new TokenClient(executor(), time, metadata);
    }

    private final MetadataCache metadata = new MetadataCache(time);

    private static List<String> paths(StubServer server) {
        List<String> out = new ArrayList<String>();
        for (StubServer.Recorded r : server.requests()) {
            out.add(r.path);
        }
        return out;
    }

    /** The decoded {@code id:secret} of a Basic header, still form-encoded as sent. */
    private static String basicCredentials(StubServer.Recorded r) {
        String header = r.header("Authorization");
        assertTrue(header != null && header.startsWith("Basic "), String.valueOf(header));
        return new String(Base64.getDecoder().decode(header.substring(6)), StandardCharsets.UTF_8);
    }
}
