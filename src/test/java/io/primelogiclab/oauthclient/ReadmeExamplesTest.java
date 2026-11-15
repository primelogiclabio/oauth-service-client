package io.primelogiclab.oauthclient;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URLEncoder;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * The README's DocuSign and Salesforce examples, line for line where it runs without the vendor: keep the two
 * in sync. The vendor values come from docs/services.md.
 */
@Timeout(60)
class ReadmeExamplesTest {

    private static final String INTEGRATION_KEY = "0a1b2c3d-integration-key";
    private static final String USER_ID = "4e5f6a7b-user-guid";

    @Test
    void theDocuSignExampleBuildsAndSignsWhatDocuSignExpects() throws Exception {
        ClientInfo docusign = ClientInfo.forTenant("docusign", "acme")
                .tokenUrl("https://account-d.docusign.com/oauth/token")
                .grant(Grant.JWT_BEARER)
                .clientId(INTEGRATION_KEY)
                .signingKey(Fixtures.rsaKey())                               // the README: ClientKey.fromPem(rsaPrivateKeyPem)
                .subject(USER_ID)
                .assertionAudience("account-d.docusign.com")
                .assertionClaim("scope", "signature impersonation")
                .allowedHost("account-d.docusign.com", "*.docusign.net")
                .build();

        TestJwt assertion = TestJwt.parse(JwtAssertion.grantAssertion(docusign, Instant.now()));
        assertEquals("RS256", assertion.header.get("alg"));
        assertEquals(INTEGRATION_KEY, assertion.claims.get("iss"));
        assertEquals(USER_ID, assertion.claims.get("sub"));
        assertEquals("account-d.docusign.com", assertion.claims.get("aud"));
        assertEquals("signature impersonation", assertion.claims.get("scope"));

        // userinfo on the auth host, and the account's base URI on a regional docusign.net host
        for (String host : new String[] {"account-d.docusign.com", "demo.docusign.net", "na3.docusign.net", "eu.docusign.net"}) {
            assertTrue(docusign.allowsHost(host), host);
        }
        assertFalse(docusign.allowsHost("docusign.net.evil.example"));
        assertFalse(docusign.allowsHost("account.docusign.com"), "production is its own ClientInfo");
    }

    @Test
    void theSalesforceExampleRunsAgainstAStandIn() throws Exception {
        try (StubServer salesforce = new StubServer(TestTls.serverContext(), false)) {
            // Salesforce's token answer: instance_url, and no expires_in
            String tokenAnswer = "{\"access_token\":\"%s\",\"instance_url\":\"" + salesforce.url("")
                    + "\",\"id\":\"https://login.salesforce.com/id/00D/005\",\"token_type\":\"Bearer\",\"scope\":\"api\"}";
            salesforce.enqueue("/services/oauth2/token", StubServer.json(200, String.format(tokenAnswer, "sf-1")));
            salesforce.enqueue("/services/oauth2/token", StubServer.json(200, String.format(tokenAnswer, "sf-2")));
            salesforce.enqueue("/services/data/v62.0/query", StubServer.json(200, "{\"totalSize\":1,\"records\":[]}"));
            salesforce.enqueue("/services/data/v62.0/sobjects/Account", StubServer.json(401,
                    "[{\"errorCode\":\"INVALID_SESSION_ID\"}]"));
            salesforce.enqueue("/services/data/v62.0/sobjects/Account", StubServer.json(201, "{\"id\":\"001\",\"success\":true}"));

            ClientInfo info = ClientInfo.global("salesforce")
                    .tokenUrl(salesforce.url("/services/oauth2/token"))          // the README: login.salesforce.com
                    .grant(Grant.JWT_BEARER)
                    .clientId("3MVG9-consumer-key")
                    .signingKey(Fixtures.rsaKey())
                    .subject("integration@example.com")
                    .assertionAudience("https://login.salesforce.com")
                    .allowedHost("*.my.salesforce.com", "localhost")             // localhost: the stand-in only
                    .build();
            String apiVersion = "v62.0";

            try (OAuthServiceClient service = client()) {
                service.initialize(info);
                String api = service.token().getField("instance_url") + "/services/data/" + apiVersion;
                ServiceResponse accounts = service.get(api + "/query?q="
                        + URLEncoder.encode("SELECT Id, Name FROM Account", "UTF-8"));
                ServiceResponse created = service.post(api + "/sobjects/Account", "{\"Name\":\"Acme\"}");

                assertEquals(200, accounts.getStatus());
                assertEquals(201, created.getStatus(), "renewed after Salesforce's 401 and sent again");
                assertNull(service.token().getExpiresAt(), "no expires_in: kept until a 401");
                assertEquals("sf-2", service.token().getValue());
            }

            List<StubServer.Recorded> requests = salesforce.requests();
            assertEquals("urn:ietf:params:oauth:grant-type:jwt-bearer", requests.get(0).param("grant_type"));
            assertNull(requests.get(0).param("scope"), "no scopes in the request");
            assertEquals("Bearer sf-1", requests.get(1).header("Authorization"));
            assertEquals("Bearer sf-2", requests.get(4).header("Authorization"));
        }
        assertTrue(ClientInfo.global("salesforce").tokenUrl("https://login.salesforce.com/services/oauth2/token")
                .grant(Grant.JWT_BEARER).clientId("3MVG9-consumer-key").signingKey(Fixtures.rsaKey())
                .subject("integration@example.com").assertionAudience("https://login.salesforce.com")
                .allowedHost("*.my.salesforce.com").build()
                .allowsHost("acme--uat.sandbox.my.salesforce.com"), "sandboxes are below my.salesforce.com too");
    }

    private static OAuthServiceClient client() {
        UrlConnectionTransport transport = new UrlConnectionTransport(Duration.ofSeconds(5), Duration.ofSeconds(10),
                null, TestTls.clientTrust());
        TokenClient tokens = new TokenClient(new HttpExecutor(transport, TokenClient.MAX_RETRIES, TokenClient.RETRY_BACKOFF,
                millis -> { }, Duration.ofSeconds(20)), Clock.systemUTC());
        HttpExecutor http = new HttpExecutor(transport, 2, Duration.ofMillis(500), millis -> { }, Duration.ofSeconds(20));
        return new OAuthServiceClient(new TokenCache(), tokens, http, OAuthServiceClient.MAX_RESPONSE_BYTES);
    }
}
