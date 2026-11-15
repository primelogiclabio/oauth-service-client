package io.primelogiclab.oauthclient;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Live token requests against the throwaway Keycloak described in the README ("Live check against
 * Keycloak"). Skipped unless {@code -Dkeycloak.https.url=https://localhost:8445} is set.
 */
class KeycloakTokenTest {

    private static final String REALM = "oauth-service-client-it";
    private static final List<String> NO_SCOPES = Collections.emptyList();

    private final List<Long> sleeps = Collections.synchronizedList(new ArrayList<Long>());
    private String base;
    private TokenClient client;

    @BeforeEach
    void keycloak() {
        String url = System.getProperty("keycloak.https.url");
        assumeTrue(url != null && !url.trim().isEmpty(), "set -Dkeycloak.https.url to run the Keycloak checks");
        base = url.trim().replaceAll("/+$", "");
        client = new TokenClient(executor(), Clock.systemUTC());
    }

    @Test
    void clientCredentialsWithTheSecretInABasicHeaderOrTheBody() {
        for (boolean inBody : new boolean[] {false, true}) {
            Instant before = Instant.now();
            AccessToken token = client.fetch(secretClient("service-client", "service-dev-secret").clientSecretInBody(inBody)
                    .build(), NO_SCOPES);
            TestJwt jwt = TestJwt.parse(token.getValue());
            assertEquals("service-client", jwt.claims.get("azp"));
            // the realm's tokens live 300 s; the expiry comes from the JWT's exp
            Duration lifetime = Duration.between(before, token.getExpiresAt());
            assertTrue(lifetime.getSeconds() > 250 && lifetime.getSeconds() <= 301, lifetime.toString());
        }
    }

    @Test
    void aWrongSecretIsAnOAuthErrorAndIsNotRetried() {
        OAuthServiceException e = assertThrows(OAuthServiceException.class,
                () -> client.fetch(secretClient("service-client", "wrong").build(), NO_SCOPES));
        assertEquals(401, e.getHttpStatus());
        assertNotNull(e.getError());
        assertFalse(e.getMessage().contains("wrong"), e.getMessage());
        assertEquals(Collections.emptyList(), sleeps);
    }

    @Test
    void theAppsScopesAreRequested() {
        ClientInfo info = secretClient("service-client", "service-dev-secret").build();
        TokenCache cache = new TokenCache();
        assertFalse(cache.get(info, client).getScope().contains("phone"));
        // phone is one of Keycloak's optional client scopes: granted only when asked for
        assertTrue(cache.get(info, Arrays.asList("phone"), client).getScope().contains("phone"));
    }

    @Test
    void privateKeyJwtWithAnRsaCertificateCredential() {
        AccessToken token = client.fetch(ClientInfo.global("keycloak").tokenUrl(tokenUrl()).clientId("jwt-client")
                .signingKey(Fixtures.clientWithChain()).build(), NO_SCOPES);
        assertEquals("jwt-client", TestJwt.parse(token.getValue()).claims.get("azp"));
    }

    @Test
    void privateKeyJwtWithAnEcKey() {
        AccessToken token = client.fetch(ClientInfo.global("keycloak").tokenUrl(tokenUrl()).clientId("jwt-ec-client")
                .signingKey(Fixtures.selfSignedEc()).build(), NO_SCOPES);
        assertEquals("jwt-ec-client", TestJwt.parse(token.getValue()).claims.get("azp"));
    }

    @Test
    void mutualTlsGivesACertificateBoundToken() {
        ClientKey certificate = Fixtures.clientWithChain();
        AccessToken token = client.fetch(ClientInfo.global("keycloak").tokenUrl(tokenUrl()).clientId("mtls-client")
                .clientCertificate(certificate).build(), NO_SCOPES);
        Map<?, ?> cnf = (Map<?, ?>) TestJwt.parse(token.getValue()).claims.get("cnf");
        assertEquals(Certificates.thumbprintS256(certificate.getCertificateChain().get(0)), cnf.get("x5t#S256"));
    }

    @Test
    void jwtBearerGrantWithClientAuthentication() {
        // Keycloak's JWT Authorization Grant: the assertion's iss is an identity provider trusting the
        // test key, sub the user's ID there (jane is linked as jane-ext), aud the realm's issuer
        AccessToken token = client.fetch(ClientInfo.global("keycloak").tokenUrl(tokenUrl()).grant(Grant.JWT_BEARER)
                .clientId("https://jwt-bearer-client.example.com").clientSecret("jwt-bearer-dev-secret")
                .signingKey(Fixtures.rsaKey()).subject("jane-ext").assertionAudience(base + "/realms/" + REALM)
                .build(), NO_SCOPES);
        assertEquals("jane", TestJwt.parse(token.getValue()).claims.get("preferred_username"));
    }

    @Test
    void refreshTokenGrant() {
        String refreshToken = passwordGrantRefreshToken();
        AccessToken token = client.fetch(secretClient("password-client", "password-dev-secret").grant(Grant.REFRESH_TOKEN)
                .refreshToken(refreshToken).subject("jane").build(), NO_SCOPES);
        assertEquals("jane", TestJwt.parse(token.getValue()).claims.get("preferred_username"));
        assertNotNull(token.getField("refresh_token"), "the new refresh token reaches the caller");
    }

    @Test
    void aTokenTheServiceTurnsAwayIsRenewedOnceAndTheCallSentAgain() {
        ClientInfo info = secretClient("service-client", "service-dev-secret").scope("openid").build();
        OAuthServiceClient service = new OAuthServiceClient(new TokenCache(), client, executor(),
                OAuthServiceClient.MAX_RESPONSE_BYTES);
        service.initialize(info);
        String userinfo = base + "/realms/" + REALM + "/protocol/openid-connect/userinfo";
        ServiceResponse before = service.get(userinfo);
        assertEquals(200, before.getStatus(), before.getBody());
        AccessToken first = service.token();

        revoke(first.getValue()); // Keycloak now answers 401 to it
        ServiceResponse after = service.get(userinfo);

        assertEquals(200, after.getStatus(), after.getBody());
        assertNotEquals(first.getValue(), service.token().getValue());
    }

    @Test
    void aCertificateBoundTokenWorksOnlyWithItsCertificate() {
        ClientInfo info = ClientInfo.global("keycloak-mtls").tokenUrl(tokenUrl()).clientId("mtls-client")
                .clientCertificate(Fixtures.clientWithChain()).scope("openid").build();
        OAuthServiceClient service = new OAuthServiceClient(new TokenCache(), client, executor(),
                OAuthServiceClient.MAX_RESPONSE_BYTES);
        service.initialize(info);
        String userinfo = base + "/realms/" + REALM + "/protocol/openid-connect/userinfo";

        // the library presents the client certificate on the service call too (RFC 8705)
        ServiceResponse withCertificate = service.get(userinfo);
        assertEquals(200, withCertificate.getStatus(), withCertificate.getBody());

        // the same token from a client without the certificate: Keycloak enforces the binding
        OAuthServiceClient withoutCertificate = new OAuthServiceClient(new TokenCache(), client, executor(),
                OAuthServiceClient.MAX_RESPONSE_BYTES);
        ServiceResponse refused = withoutCertificate.get(service.token().getValue(), userinfo);
        assertEquals(401, refused.getStatus(), refused.getBody());
    }

    // ------------------------------------------------------------------ helpers

    private String tokenUrl() {
        return base + "/realms/" + REALM + "/protocol/openid-connect/token";
    }

    private ClientInfo.Builder secretClient(String clientId, String secret) {
        return ClientInfo.global("keycloak").tokenUrl(tokenUrl()).clientId(clientId).clientSecret(secret);
    }

    private HttpExecutor executor() {
        HttpTransport transport = new UrlConnectionTransport(Duration.ofSeconds(10), Duration.ofSeconds(30),
                Duration.ofSeconds(60), TestTls.clientTrust());
        return new HttpExecutor(transport, TokenClient.MAX_RETRIES, TokenClient.RETRY_BACKOFF,
                millis -> sleeps.add(millis), Duration.ofSeconds(60));
    }

    /** Revokes an access token (RFC 7009) as service-client. */
    private void revoke(String accessToken) {
        final Map<String, String> headers = new LinkedHashMap<String, String>();
        headers.put("Content-Type", "application/x-www-form-urlencoded");
        headers.put("Authorization", "Basic " + java.util.Base64.getEncoder().encodeToString(
                "service-client:service-dev-secret".getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        final String form = "token=" + TokenClient.formEncode(accessToken) + "&token_type_hint=access_token";
        HttpResponse response = executor().execute(new Supplier<HttpRequest>() {
            @Override
            public HttpRequest get() {
                return HttpRequest.post(base + "/realms/" + REALM + "/protocol/openid-connect/revoke", headers, form);
            }
        }, HttpExecutor.Retry.NEVER);
        assertEquals(200, response.getStatus(), response.getBody());
    }

    /** jane's refresh token from the password grant, which the library itself doesn't offer. */
    private String passwordGrantRefreshToken() {
        final Map<String, String> headers = new LinkedHashMap<String, String>();
        headers.put("Content-Type", "application/x-www-form-urlencoded");
        final String form = "grant_type=password&username=jane&password=jane-dev-password"
                + "&client_id=password-client&client_secret=password-dev-secret";
        HttpResponse response = executor().execute(new Supplier<HttpRequest>() {
            @Override
            public HttpRequest get() {
                return HttpRequest.post(tokenUrl(), headers, form);
            }
        }, HttpExecutor.Retry.NEVER);
        assertEquals(200, response.getStatus(), response.getBody());
        return (String) Json.parseObject(response.getBody()).get("refresh_token");
    }
}
