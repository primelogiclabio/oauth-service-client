package io.primelogiclab.oauthclient;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Collections;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import io.primelogiclab.oauthclient.ClientInfo.ClientAuthentication;

class ClientInfoTest {

    private static final String TOKEN_URL = "https://idp.example.com/oauth2/token";

    // --- one valid build per kind of service ---

    @Test
    void docuSignStyleJwtBearerPerTenant() {
        ClientKey key = Fixtures.rsaKey();
        ClientInfo info = ClientInfo.forTenant(" docusign ", " acme ")
                .tokenUrl("https://account-d.docusign.com/oauth/token")
                .grant(Grant.JWT_BEARER)
                .clientId("integration-key")
                .signingKey(key)
                .subject("user-guid")
                .assertionAudience("account-d.docusign.com")
                .assertionClaim(" scope ", "signature impersonation")
                .attribute("accountId", "12345")
                .build();
        assertEquals("docusign", info.getService());
        assertEquals("acme", info.getTenant());
        assertFalse(info.isGlobal());
        assertEquals(Grant.JWT_BEARER, info.getGrant());
        assertEquals("urn:ietf:params:oauth:grant-type:jwt-bearer", info.getGrant().getValue());
        assertSame(key, info.getSigningKey());
        assertEquals("user-guid", info.getSubject());
        assertEquals("account-d.docusign.com", info.getAssertionAudience());
        assertEquals(Collections.singletonMap("scope", "signature impersonation"), info.getAssertionClaims());
        assertTrue(info.getScopes().isEmpty(), "DocuSign takes scopes in the assertion, not the form");
        assertEquals("12345", info.getAttribute("accountId"));
        assertNull(info.getAttribute("missing"));
        assertEquals(ClientAuthentication.NONE, info.clientAuthentication());
    }

    @Test
    void salesforceStyleJwtBearerAndClientCredentialsGlobal() {
        ClientInfo jwt = ClientInfo.global("salesforce")
                .tokenUrl("https://login.salesforce.com/services/oauth2/token")
                .grant(Grant.JWT_BEARER)
                .clientId("consumer-key")
                .signingKey(Fixtures.rsaKey())
                .subject("integration@example.com")
                .assertionAudience("https://login.salesforce.com")
                .build();
        assertTrue(jwt.isGlobal());
        assertNull(jwt.getTenant());
        assertTrue(jwt.getScopes().isEmpty());

        ClientInfo secret = ClientInfo.global("salesforce")
                .tokenUrl("https://example.my.salesforce.com/services/oauth2/token")
                .clientId("consumer-key")
                .clientSecret("consumer-secret")
                .build();
        assertEquals(Grant.CLIENT_CREDENTIALS, secret.getGrant());
        assertEquals("client_credentials", secret.getGrant().getValue());
        assertFalse(secret.isClientSecretInBody());
        assertEquals(ClientAuthentication.CLIENT_SECRET_BASIC, secret.clientAuthentication());
    }

    @Test
    void vertexStyleClientCredentialsWithSecretAndAudience() {
        ClientInfo info = ClientInfo.forTenant("vertex", "acme")
                .tokenUrl("https://auth.vertexcloud.com/oauth/token")
                .clientId("client")
                .clientSecret("secret")
                .tokenParameter("audience", "verx://migration-api")
                .scope("payroll-calculation-test")
                .build();
        assertEquals("secret", info.getClientSecret());
        assertEquals(Collections.singletonMap("audience", "verx://migration-api"), info.getTokenParameters());
        assertEquals(ClientAuthentication.CLIENT_SECRET_BASIC, info.clientAuthentication());
    }

    @Test
    void auth0StyleClientCredentialsWithAudience() {
        ClientInfo secret = ClientInfo.forTenant("auth0", "acme")
                .tokenUrl("https://acme.us.auth0.com/oauth/token")
                .clientId("client")
                .clientSecret("secret")
                .tokenParameter("audience", "https://api.example.com")
                .build();
        assertEquals(Collections.singletonMap("audience", "https://api.example.com"), secret.getTokenParameters());
        assertEquals(ClientAuthentication.CLIENT_SECRET_BASIC, secret.clientAuthentication());

        ClientInfo privateKeyJwt = ClientInfo.forTenant("auth0", "acme")
                .tokenUrl("https://acme.us.auth0.com/oauth/token")
                .clientId("client")
                .signingKey(Fixtures.rsaKey().withKeyId("auth0-kid"))
                .assertionAudience("https://acme.us.auth0.com/")
                .tokenParameter("audience", "https://api.example.com")
                .build();
        assertEquals("https://acme.us.auth0.com/", privateKeyJwt.getAssertionAudience(), "trailing slash kept");
        assertEquals(ClientAuthentication.PRIVATE_KEY_JWT, privateKeyJwt.clientAuthentication());
    }

    @Test
    void oicStyleClientCredentialsAndUserAssertion() {
        String scope = "https://abc123.integration.ocp.oraclecloud.com:443urn:opc:resource:consumer::all";
        ClientInfo secret = ClientInfo.global("oic")
                .tokenUrl("https://idcs-abc.identity.oraclecloud.com/oauth2/v1/token")
                .clientId("client")
                .clientSecret("secret")
                .scope(scope)
                .build();
        assertEquals(Collections.singletonList(scope), secret.getScopes());
        assertEquals(ClientAuthentication.CLIENT_SECRET_BASIC, secret.clientAuthentication());

        ClientInfo userAssertion = ClientInfo.forTenant("oic", "acme")
                .tokenUrl("https://idcs-abc.identity.oraclecloud.com/oauth2/v1/token")
                .grant(Grant.JWT_BEARER)
                .clientId("client")
                .clientSecret("secret")
                .signingKey(Fixtures.rsaKey().withKeyId("cert-alias"))
                .subject("integration.user")
                .assertionAudience("https://idcs-abc.identity.oraclecloud.com")
                .scope(scope)
                .build();
        assertEquals(ClientAuthentication.CLIENT_SECRET_BASIC, userAssertion.clientAuthentication(),
                "the secret authenticates the client; the signing key signs the user assertion");
    }

    @Test
    void entraStyleCertificateCredentialIsPrivateKeyJwt() {
        ClientKey cert = ClientKey.fromKeyStore(Fixtures.pkcs12("client.p12"), Fixtures.PASSWORD);
        ClientInfo info = ClientInfo.global("graph")
                .tokenUrl("https://login.microsoftonline.com/directory-id/oauth2/v2.0/token")
                .clientId("application-id")
                .signingKey(cert)
                .scope("https://graph.microsoft.com/.default")
                .build();
        assertTrue(info.getSigningKey().hasCertificate());
        assertNull(info.getAssertionAudience(), "defaults to the token URL in the token request");
        assertEquals(ClientAuthentication.PRIVATE_KEY_JWT, info.clientAuthentication());
    }

    @Test
    void oktaStylePrivateKeyJwtWithKeyId() {
        ClientInfo info = ClientInfo.forTenant("okta", "acme")
                .tokenUrl("https://acme.okta.com/oauth2/default/v1/token")
                .clientId("client")
                .signingKey(ClientKey.fromPem(Fixtures.text("client.key")).withKeyId("kid-1"))
                .assertionAudience("https://acme.okta.com/oauth2/default/v1/token")
                .scope("custom.read")
                .build();
        assertEquals("kid-1", info.getSigningKey().getKeyId());
        assertEquals(ClientAuthentication.PRIVATE_KEY_JWT, info.clientAuthentication());
    }

    @Test
    void jiraStyleServiceAccountSendsTheSecretInTheBody() {
        ClientInfo info = ClientInfo.forTenant("jira", "acme")
                .tokenUrl("https://auth.atlassian.com/oauth/token")
                .clientId("client")
                .clientSecret("secret")
                .clientSecretInBody(true)
                .attribute("cloudId", "cloud-id")
                .build();
        assertTrue(info.isClientSecretInBody());
        assertEquals(ClientAuthentication.CLIENT_SECRET_POST, info.clientAuthentication());
    }

    @Test
    void refreshTokenWithSecretAndPublicClient() {
        ClientInfo confidential = ClientInfo.forTenant("jira", "acme")
                .tokenUrl("https://auth.atlassian.com/oauth/token")
                .grant(Grant.REFRESH_TOKEN)
                .clientId("client")
                .clientSecret("secret")
                .refreshToken("refresh")
                .subject("user-1")
                .scope("read:jira-work", "offline_access")
                .build();
        assertEquals("refresh", confidential.getRefreshToken());
        assertEquals("refresh_token", confidential.getGrant().getValue());
        assertEquals(ClientAuthentication.CLIENT_SECRET_BASIC, confidential.clientAuthentication());

        ClientInfo publicClient = ClientInfo.forTenant("jira", "acme")
                .tokenUrl(TOKEN_URL).grant(Grant.REFRESH_TOKEN).clientId("client").refreshToken("refresh")
                .subject("user-1").build();
        assertEquals(ClientAuthentication.NONE, publicClient.clientAuthentication());
    }

    @Test
    void refreshTokenGrantNeedsTheUser() {
        assertProblem(ClientInfo.forTenant("jira", "acme").tokenUrl(TOKEN_URL).grant(Grant.REFRESH_TOKEN)
                .clientId("client").refreshToken("refresh"), "REFRESH_TOKEN needs a subject");
    }

    @Test
    void theUserIsPartOfTheCacheKeyExceptForClientCredentials() {
        ClientInfo refresh = ClientInfo.forTenant("jira", "acme").tokenUrl(TOKEN_URL).grant(Grant.REFRESH_TOKEN)
                .clientId("client").refreshToken("refresh").subject("alice").build();
        ClientInfo bearer = signingClient().subject("bob").build();
        ClientInfo bearerAsClient = signingClient().subject(null).build();
        assertEquals("alice", refresh.cacheUser());
        assertEquals("bob", bearer.cacheUser());
        assertNull(bearerAsClient.cacheUser());
        assertNull(secretClient().build().cacheUser());
    }

    @Test
    void keycloakStyleMutualTls() {
        ClientKey cert = Fixtures.selfSignedEc();
        ClientInfo info = ClientInfo.global("keycloak")
                .tokenUrl(TOKEN_URL).clientId("client").clientCertificate(cert).build();
        assertSame(cert, info.getClientCertificate());
        assertEquals(ClientAuthentication.MUTUAL_TLS, info.clientAuthentication());

        ClientInfo secretAndCert = ClientInfo.global("keycloak")
                .tokenUrl(TOKEN_URL).clientId("client").clientSecret("secret").clientCertificate(cert).build();
        assertEquals(ClientAuthentication.CLIENT_SECRET_BASIC, secretAndCert.clientAuthentication());
        assertSame(cert, secretAndCert.getClientCertificate(), "still presented for certificate-bound tokens");

        ClientInfo jwtAndSecret = ClientInfo.global("idp")
                .tokenUrl(TOKEN_URL).grant(Grant.JWT_BEARER).clientId("client").clientSecret("secret")
                .signingKey(Fixtures.rsaKey()).assertionAudience("idp").clientSecretInBody(true).build();
        assertEquals(ClientAuthentication.CLIENT_SECRET_POST, jwtAndSecret.clientAuthentication());
    }

    // --- validation ---

    @Test
    void reportsEveryProblemAtOnce() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> ClientInfo.forTenant(" ", null).build());
        String m = e.getMessage();
        assertTrue(m.startsWith("Invalid ClientInfo for ?/?: "), m);
        for (String expected : new String[] {"service is required", "tenant is required", "tokenUrl is required",
                "clientId is required", "CLIENT_CREDENTIALS needs a clientSecret, signingKey or clientCertificate"}) {
            assertTrue(m.contains(expected), m);
        }
    }

    @Test
    void messageNamesTheServiceAndTenantOrGlobal() {
        assertTrue(assertThrows(IllegalArgumentException.class, () -> ClientInfo.forTenant("docusign", "acme").build())
                .getMessage().startsWith("Invalid ClientInfo for docusign/acme: "));
        assertTrue(assertThrows(IllegalArgumentException.class, () -> ClientInfo.global("salesforce").build())
                .getMessage().startsWith("Invalid ClientInfo for salesforce (global): "));
    }

    @ParameterizedTest
    @CsvSource(delimiter = '|', value = {
            "http://idp.example.com/token|must be an https URL",
            "ftp://idp.example.com/token|must be an https URL",
            "/oauth/token|must be an https URL",
            "https://user:pa55word@idp.example.com/token|must not contain user info",
            "https://idp.example.com\\@evil.example/token|must not contain a backslash",
            "https://idp.example.com/token#frag|must not have a fragment",
            "https://idp example.com/token|is not a valid URL",
            "https:token|must have a host"})
    void rejectsBadTokenUrls(String url, String problem) {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> secretClient().tokenUrl(url).build());
        assertTrue(e.getMessage().contains("tokenUrl " + problem), e.getMessage());
        assertFalse(e.getMessage().contains("pa55word"), e.getMessage());
    }

    @ParameterizedTest
    @ValueSource(strings = {"https://idp.example.com/token?tenant=acme", "HTTPS://IDP.example.com:8443/token",
            "https://[::1]/token"})
    void acceptsHttpsUrlsWithQueryPortOrIpLiteral(String url) {
        assertEquals(url, secretClient().tokenUrl(url).build().getTokenUrl());
    }

    @Test
    void jwtBearerNeedsSigningKeyAndAudience() {
        String m = assertThrows(IllegalArgumentException.class, () -> ClientInfo.global("idp")
                .tokenUrl(TOKEN_URL).grant(Grant.JWT_BEARER).clientId("client").build()).getMessage();
        assertTrue(m.contains("JWT_BEARER needs a signingKey"), m);
        assertTrue(m.contains("JWT_BEARER needs an assertionAudience"), m);
    }

    @Test
    void refreshTokenGrantNeedsRefreshToken() {
        String m = assertThrows(IllegalArgumentException.class, () -> ClientInfo.global("idp")
                .tokenUrl(TOKEN_URL).grant(Grant.REFRESH_TOKEN).clientId("client").build()).getMessage();
        assertTrue(m.contains("REFRESH_TOKEN needs a refreshToken"), m);
    }

    @Test
    void rejectsSettingsTheGrantDoesNotUse() {
        assertProblem(secretClient().signingKey(Fixtures.rsaKey()), "set clientSecret or signingKey, not both");
        assertProblem(secretClient().grant(Grant.REFRESH_TOKEN).refreshToken("r").subject("u").signingKey(Fixtures.rsaKey()),
                "set clientSecret or signingKey, not both");
        assertProblem(secretClient().subject("user"), "subject is only used with JWT_BEARER and REFRESH_TOKEN");
        assertProblem(secretClient().assertionAudience("aud"), "assertionAudience is only used with a signingKey");
        assertProblem(secretClient().refreshToken("r"), "refreshToken is only used with REFRESH_TOKEN");
        assertProblem(ClientInfo.global("idp").tokenUrl(TOKEN_URL).grant(Grant.JWT_BEARER).clientId("client")
                .signingKey(Fixtures.rsaKey()).assertionAudience("aud").refreshToken("r"),
                "refreshToken is only used with REFRESH_TOKEN");
        assertProblem(secretClient().clientCertificate(Fixtures.rsaKey()),
                "clientCertificate needs a ClientKey with a certificate");
        assertProblem(secretClient().grant(null), "grant is required");
        assertProblem(ClientInfo.global("idp").tokenUrl(TOKEN_URL).clientId("client")
                .clientCertificate(Fixtures.clientWithChain()).clientSecretInBody(true),
                "clientSecretInBody is only used with a clientSecret");
        assertProblem(secretClient().assertionClaim("scope", "a b"), "assertionClaim is only used with a signingKey");
        secretClient().clientSecretInBody(false).build();
    }

    @Test
    void assertionClaimsRejectReservedNamesAndCanBeReplaced() {
        for (String name : new String[] {"iss", "exp", "iat", "nbf", "jti", "JTI"}) {
            assertProblem(signingClient().assertionClaim(name, "x"), "assertionClaim '" + name + "' is set by the library");
        }
        assertProblem(signingClient().assertionClaim("sub", "x"), "assertionClaim 'sub' is set by the library; use subject(...)");
        assertProblem(signingClient().assertionClaim("aud", "x"),
                "assertionClaim 'aud' is set by the library; use assertionAudience(...)");
        assertProblem(signingClient().assertionClaim(" ", "x"), "assertionClaim name must not be blank");
        assertProblem(signingClient().assertionClaim("scope", null), "assertionClaim 'scope' needs a value");
        ClientInfo info = signingClient().assertionClaim("scope", "a").assertionClaim(" scope ", "a b")
                .assertionClaim("grant_type", "fine here: only form fields are reserved for this").build();
        assertEquals("a b", info.getAssertionClaims().get("scope"));
        assertEquals(2, info.getAssertionClaims().size());
    }

    @Test
    void rejectsExpiredCertificates() {
        Clock after = Clock.fixed(Instant.parse("2040-01-01T00:00:00Z"), ZoneOffset.UTC);
        ClientInfo.Builder mtls = ClientInfo.global("idp").tokenUrl(TOKEN_URL).clientId("client")
                .clientCertificate(Fixtures.clientWithChain());
        mtls.build(); // valid today
        String m = assertThrows(IllegalArgumentException.class, () -> mtls.build(after)).getMessage();
        assertTrue(m.contains("clientCertificate certificate") && m.contains("CN=test-client") && m.contains("expired on"), m);

        ClientInfo.Builder signing = ClientInfo.global("idp").tokenUrl(TOKEN_URL).clientId("client")
                .signingKey(Fixtures.clientWithChain());
        m = assertThrows(IllegalArgumentException.class, () -> signing.build(after)).getMessage();
        assertTrue(m.contains("signingKey certificate"), m);

        ClientInfo.global("idp").tokenUrl(TOKEN_URL).clientId("client").signingKey(Fixtures.rsaKey()).build(after);
    }

    @Test
    void scopesAreTrimmedDeduplicatedAndSingleWords() {
        ClientInfo info = secretClient().scope(" a ", "b").scope("a", "c").build();
        assertEquals(Arrays.asList("a", "b", "c"), info.getScopes());
        assertProblem(secretClient().scope("signature impersonation"),
                "scope 'signature impersonation' must not contain spaces; pass each scope separately");
        assertProblem(secretClient().scope("a", " "), "scope must not be blank");
        assertProblem(secretClient().scope((String[]) null), "scope must not be blank");
    }

    @Test
    void theAppsScopesReplaceTheDefaultsAndAreCheckedTheSameWay() {
        ClientInfo info = secretClient().scope("default").build();
        assertEquals(Arrays.asList("default"), info.effectiveScopes(null));
        assertEquals(Arrays.asList("default"), info.effectiveScopes(Collections.<String>emptyList()));
        assertEquals(Arrays.asList("b", "a"), info.effectiveScopes(Arrays.asList(" b ", "a", "b")));
        assertEquals(Collections.emptyList(), secretClient().build().effectiveScopes(null));
        String m = assertThrows(IllegalArgumentException.class,
                () -> info.effectiveScopes(Arrays.asList("a b", " "))).getMessage();
        assertTrue(m.contains("scope 'a b' must not contain spaces") && m.contains("scope must not be blank"), m);
        assertThrows(UnsupportedOperationException.class, () -> info.effectiveScopes(Arrays.asList("x")).add("y"));
    }

    @Test
    void tokenParametersRejectReservedNamesAndCanBeReplaced() {
        assertProblem(secretClient().tokenParameter("grant_type", "x"), "tokenParameter 'grant_type' is set by the library");
        assertProblem(secretClient().tokenParameter("client_secret", "x"), "tokenParameter 'client_secret' is set by the library");
        assertProblem(secretClient().tokenParameter("Scope", "x"), "tokenParameter 'Scope' is set by the library; use scope(...)");
        assertProblem(secretClient().tokenParameter(" ", "x"), "tokenParameter name must not be blank");
        assertProblem(secretClient().tokenParameter("audience", null), "tokenParameter 'audience' needs a value");
        ClientInfo info = secretClient().tokenParameter("audience", null).tokenParameter(" audience ", "api").build();
        assertEquals(Collections.singletonMap("audience", "api"), info.getTokenParameters());
    }

    @Test
    void attributesAreCallerDataWithNamesAndValues() {
        assertProblem(secretClient().attribute(null, "x"), "attribute name must not be blank");
        assertProblem(secretClient().attribute("accountId", null), "attribute 'accountId' needs a value");
        ClientInfo info = secretClient().attribute("baseUrl", "https://api.example.com").attribute("baseUrl", "https://eu.example.com")
                .attribute("grant_type", "fine here: attributes are never sent").build();
        assertEquals("https://eu.example.com", info.getAttribute("baseUrl"));
        assertEquals(2, info.getAttributes().size());
    }

    // --- immutability and logging ---

    @Test
    void builtInstanceIsImmutableAndIndependentOfTheBuilder() {
        ClientInfo.Builder b = secretClient().scope("a").tokenParameter("audience", "api").attribute("k", "v");
        ClientInfo first = b.build();
        b.scope("b").tokenParameter("resource", "r").attribute("k2", "v2").clientSecret("other");
        ClientInfo second = b.build();

        assertEquals(Collections.singletonList("a"), first.getScopes());
        assertEquals(1, first.getTokenParameters().size());
        assertEquals(1, first.getAttributes().size());
        assertEquals("secret", first.getClientSecret());
        assertEquals(Arrays.asList("a", "b"), second.getScopes());
        assertEquals("other", second.getClientSecret());

        assertThrows(UnsupportedOperationException.class, () -> first.getScopes().add("x"));
        assertThrows(UnsupportedOperationException.class, () -> first.getTokenParameters().put("x", "y"));
        assertThrows(UnsupportedOperationException.class, () -> first.getAttributes().clear());

        ClientInfo.Builder sb = signingClient().assertionClaim("scope", "a");
        ClientInfo signed = sb.build();
        sb.assertionClaim("extra", "b");
        assertEquals(1, signed.getAssertionClaims().size());
        assertThrows(UnsupportedOperationException.class, () -> signed.getAssertionClaims().put("x", "y"));
    }

    @Test
    void allowedHostsAreNormalizedAndKept() {
        ClientInfo info = secretClient().allowedHost("API.Example.com.", "*.my.salesforce.com")
                .allowedHost("api.example.com", "[::1]", "10.0.0.5").build();
        assertEquals(Arrays.asList("api.example.com", "*.my.salesforce.com", "[::1]", "10.0.0.5"), info.getAllowedHosts());
        assertTrue(secretClient().build().getAllowedHosts().isEmpty());
        assertTrue(info.toString().contains("allowedHosts=[api.example.com, *.my.salesforce.com, [::1], 10.0.0.5]"),
                info.toString());
        // a token setting: a client info without the list doesn't reuse a token kept to some hosts
        assertFalse(secretClient().build().tokenSettings().equals(info.tokenSettings()));
    }

    @Test
    void malformedAllowedHostsAreAllReported() {
        String m = assertThrows(IllegalArgumentException.class, () -> secretClient().allowedHost(" ", "https://x.com",
                "x.com/path", "x.com:443", "user@x.com", "*", "*.com", "a.*.com", "x y.com", "[zz]").build()).getMessage();
        for (String part : Arrays.asList("allowedHost must not be blank",
                "#2 (not shown) must be a host name only", "#3 (not shown) must be a host name only",
                "'x.com:443' must be a host name only", "#5 (not shown) must be a host name only",
                "'*' may only use * as its first label", "'*.com' is too broad", "'a.*.com' may only use * as its first label",
                "'x y.com' is not a valid host name", "'[zz]' is not a valid IPv6 address")) {
            assertTrue(m.contains(part), part + " in " + m);
        }
    }

    @Test
    void anEntryThatMayCarryCredentialsIsNeverEchoed() {
        String m = assertThrows(IllegalArgumentException.class, () -> secretClient()
                .allowedHost("https://user:s3cr3t-pw@api.example.com/x?key=s3cr3t-key").build()).getMessage();
        assertFalse(m.contains("s3cr3t"), m);
        assertTrue(m.contains("allowedHost #1 (not shown)"), m);
    }

    @Test
    void aWildcardOverAnIpAddressIsRefused() {
        assertProblem(secretClient().allowedHost("*.0.0.1"), "'*.0.0.1' can't be a wildcard over an IP address");
        assertEquals(Arrays.asList("10.0.0.1"), secretClient().allowedHost("10.0.0.1").build().getAllowedHosts());
    }

    @Test
    void allowsHostRefusesWhatIsNotAHostName() {
        ClientInfo info = secretClient().allowedHost("*.example.com").build();
        assertFalse(info.allowsHost("evil.com/.example.com"));
        assertFalse(info.allowsHost("evil.com\\.example.com"));
        assertFalse(info.allowsHost("user@api.example.com"));
        assertFalse(info.allowsHost("*.example.com"));
        assertFalse(secretClient().build().allowsHost("evil.com/x"), "even without a list");
        assertTrue(info.allowsHost("api.example.com"));
    }

    @Test
    void allowsHostMatchesExactlyOrBelowAWildcard() {
        ClientInfo info = secretClient().allowedHost("api.example.com", "*.my.salesforce.com").build();
        assertTrue(info.allowsHost("api.example.com"));
        assertTrue(info.allowsHost("API.EXAMPLE.COM."));
        assertTrue(info.allowsHost("acme.my.salesforce.com"));
        assertTrue(info.allowsHost("eu.acme.my.salesforce.com"));
        assertFalse(info.allowsHost("my.salesforce.com"), "the wildcard is for hosts below the domain");
        assertFalse(info.allowsHost("evilmy.salesforce.com"));
        assertFalse(info.allowsHost("example.com"));
        assertFalse(info.allowsHost("api.example.com.evil.net"));
        assertFalse(info.allowsHost(null));
        assertTrue(secretClient().build().allowsHost("anything.example"), "no list: every host");
    }

    @Test
    void toStringAndErrorsNeverShowSecrets() {
        ClientKey key = Fixtures.clientWithChain();
        ClientInfo info = ClientInfo.forTenant("idp", "acme")
                .tokenUrl("https://idp.example.com/token?sig=query-secret")
                .grant(Grant.REFRESH_TOKEN)
                .clientId("client")
                .clientCertificate(key)
                .clientSecret("the-client-secret")
                .refreshToken("the-refresh-token")
                .subject("the-user")
                .tokenParameter("resource", "param-value")
                .attribute("accountId", "attribute-value")
                .scope("a")
                .build();
        String s = info.toString();
        assertTrue(s.startsWith("ClientInfo{idp/acme, grant=REFRESH_TOKEN, tokenUrl=https://idp.example.com/token,"), s);
        assertTrue(s.contains("clientSecret=****") && s.contains("refreshToken=****"), s);
        assertTrue(s.contains("clientCertificate=ClientKey{RSA key, certificate="), s);
        assertTrue(s.contains("tokenParameters=[resource]") && s.contains("attributes=[accountId]"), s);
        for (String hidden : new String[] {"the-client-secret", "the-refresh-token", "query-secret", "param-value",
                "attribute-value", "PRIVATE KEY"}) {
            assertFalse(s.contains(hidden), hidden + " in " + s);
        }
        assertTrue(secretClient().subject(null).build().toString().contains("ClientInfo{idp (global)"));
        assertTrue(secretClient().clientSecretInBody(true).build().toString().contains("clientSecret=**** (in body)"));

        String signed = signingClient().assertionClaim("scope", "claim-value").build().toString();
        assertTrue(signed.contains("assertionClaims=[scope]"), signed);
        assertFalse(signed.contains("claim-value"), signed);

        String m = assertThrows(IllegalArgumentException.class, () -> secretClient().clientSecret("the-client-secret")
                .tokenUrl("http://idp.example.com/token").build()).getMessage();
        assertFalse(m.contains("the-client-secret"), m);
    }

    @Test
    void introspectionUrlIsOptionalHttpsAndShownWithoutItsQuery() {
        assertNull(secretClient().build().getIntrospectionUrl());
        assertFalse(secretClient().build().toString().contains("introspectionUrl"));
        ClientInfo info = secretClient().introspectionUrl(" https://acme.my.salesforce.com/services/oauth2/introspect?x=secret ").build();
        assertEquals("https://acme.my.salesforce.com/services/oauth2/introspect?x=secret", info.getIntrospectionUrl());
        String s = info.toString();
        assertTrue(s.contains("introspectionUrl=https://acme.my.salesforce.com/services/oauth2/introspect"), s);
        assertFalse(s.contains("x=secret"), s);
        assertProblem(secretClient().introspectionUrl("http://acme.my.salesforce.com/introspect"), "introspectionUrl must be an https URL");
        assertProblem(secretClient().introspectionUrl("https://user@acme.example.com/introspect"), "introspectionUrl must not contain user info");
        assertNull(secretClient().introspectionUrl("  ").build().getIntrospectionUrl());
    }

    @Test
    void tokenSettingsChangeWithWhatTheTokenGrantsNotWithCredentials() {
        ClientInfo base = secretClient().scope("a").build();
        assertEquals(base.tokenSettings(), secretClient().scope("a").build().tokenSettings());
        assertEquals(base.tokenSettings(), secretClient().scope("a").clientSecret("rotated").build().tokenSettings());
        assertEquals(base.tokenSettings(), secretClient().scope("a").attribute("note", "x").build().tokenSettings());
        assertEquals(base.tokenSettings(), secretClient().scope("a").introspectionUrl("https://idp.example.com/introspect").build().tokenSettings());
        for (ClientInfo.Builder changed : Arrays.asList(
                secretClient().scope("b"),
                secretClient().scope("a").tokenUrl("https://other.example.com/token"),
                secretClient().scope("a").clientId("other"),
                secretClient().scope("a").tokenParameter("audience", "x"),
                secretClient().scope("a").clientCertificate(Fixtures.clientWithChain()))) {
            assertFalse(base.tokenSettings().equals(changed.build().tokenSettings()), changed.build().toString());
        }
        ClientInfo signed = signingClient().subject("u1").build();
        assertEquals(signed.tokenSettings(), signingClient().subject("u1").signingKey(Fixtures.clientWithChain()).build().tokenSettings());
        assertFalse(signed.tokenSettings().equals(signingClient().subject("u2").build().tokenSettings()));
        assertFalse(signed.tokenSettings().equals(signingClient().subject("u1").assertionAudience("other").build().tokenSettings()));
        assertFalse(signed.tokenSettings().equals(signingClient().subject("u1").assertionClaim("scope", "x").build().tokenSettings()));
        assertFalse(signed.tokenSettings().equals(signingClient().subject("u1").grant(Grant.CLIENT_CREDENTIALS)
                .subject(null).assertionAudience(null).build().tokenSettings()));
    }

    @Test
    void controlCharactersAreReplacedInToString() {
        ClientInfo info = ClientInfo.forTenant("idp", "ac\nme").tokenUrl(TOKEN_URL).grant(Grant.JWT_BEARER)
                .clientId("client\r\nX-Injected: 1").signingKey(Fixtures.rsaKey()).subject("user x")
                .assertionAudience("aud").build();
        String s = info.toString();
        assertFalse(s.contains("\n") || s.contains("\r") || s.contains(" "), s);
        assertTrue(s.contains("idp/ac?me") && s.contains("subject=user?x"), s);
    }

    @Test
    void theTokenEndpointIsSetOrReadFromTheServersMetadata() {
        ClientInfo byIssuer = noEndpoint().issuer(" https://login.example.com/tenant/v2.0 ").build();
        assertNull(byIssuer.getTokenUrl());
        assertEquals("https://login.example.com/tenant/v2.0", byIssuer.getIssuer());
        assertTrue(byIssuer.toString().contains("issuer=https://login.example.com/tenant/v2.0")
                && !byIssuer.toString().contains("tokenUrl"), byIssuer.toString());
        ClientInfo byDocument = noEndpoint().metadataUrl("https://idp.example.com/meta.json?key=private").build();
        assertEquals("https://idp.example.com/meta.json?key=private", byDocument.getMetadataUrl());
        assertTrue(byDocument.toString().contains("metadataUrl=https://idp.example.com/meta.json")
                && !byDocument.toString().contains("private"), byDocument.toString());
        assertEquals("https://idp.example.com", noEndpoint().issuer("https://idp.example.com")
                .metadataUrl("https://idp.example.com/m").build().getIssuer());

        assertProblem(noEndpoint(), "tokenUrl is required (or issuer or metadataUrl");
        assertProblem(noEndpoint().tokenUrl(TOKEN_URL).issuer("https://idp.example.com"),
                "set tokenUrl, or issuer and/or metadataUrl to read it from the server's metadata, not both");
        assertProblem(noEndpoint().tokenUrl(TOKEN_URL).metadataUrl("https://idp.example.com/m"), "not both");
        assertProblem(noEndpoint().issuer("http://idp.example.com"), "issuer must be an https URL");
        assertProblem(noEndpoint().issuer("https://idp.example.com?tenant=1"), "issuer must not have a query");
        assertProblem(noEndpoint().issuer("https://idp.example.com#x"), "issuer must not have a fragment");
        assertProblem(noEndpoint().metadataUrl("https://u@idp.example.com/m"), "metadataUrl must not contain user info");

        // how the endpoint is found is part of what identifies a cached token
        assertFalse(noEndpoint().issuer("https://a.example.com").build().tokenSettings()
                .equals(noEndpoint().issuer("https://b.example.com").build().tokenSettings()));
        assertFalse(noEndpoint().issuer("https://a.example.com").build().tokenSettings()
                .equals(noEndpoint().metadataUrl("https://a.example.com").build().tokenSettings()));
    }

    private static ClientInfo.Builder noEndpoint() {
        return ClientInfo.global("idp").clientId("client").clientSecret("secret");
    }

    @Test
    void maxTokenRetryDelayIsFiveMinutesUnlessSetWithinZeroToADay() {
        assertEquals(Duration.ofMinutes(5), secretClient().build().getMaxTokenRetryDelay());
        assertFalse(secretClient().build().toString().contains("maxTokenRetryDelay"));
        ClientInfo vertex = secretClient().maxTokenRetryDelay(Duration.ofHours(1)).build();
        assertEquals(Duration.ofHours(1), vertex.getMaxTokenRetryDelay());
        assertTrue(vertex.toString().contains("maxTokenRetryDelay=PT1H"), vertex.toString());
        assertEquals(Duration.ZERO, secretClient().maxTokenRetryDelay(Duration.ZERO).build().getMaxTokenRetryDelay());
        assertEquals(Duration.ofHours(24), secretClient().maxTokenRetryDelay(Duration.ofHours(24)).build().getMaxTokenRetryDelay());
        assertProblem(secretClient().maxTokenRetryDelay(null), "maxTokenRetryDelay must be 0 to 24 hours");
        assertProblem(secretClient().maxTokenRetryDelay(Duration.ofSeconds(-1)), "maxTokenRetryDelay must be 0 to 24 hours");
        assertProblem(secretClient().maxTokenRetryDelay(Duration.ofHours(24).plusNanos(1)), "maxTokenRetryDelay must be 0 to 24 hours");
        // it says how long to wait, not what the token grants
        assertEquals(secretClient().build().tokenSettings(), vertex.tokenSettings());
    }

    @Test
    void theSigningAlgorithmMustFitTheKey() {
        assertNull(signingClient().build().getSigningAlgorithm());
        assertNull(signingClient().signingAlgorithm(" ").build().getSigningAlgorithm());
        assertEquals("PS256", signingClient().signingAlgorithm(" PS256 ").build().getSigningAlgorithm());
        assertEquals("RS256", signingClient().signingAlgorithm("RS256").build().getSigningAlgorithm());
        ClientInfo.Builder ec = ClientInfo.global("okta").tokenUrl(TOKEN_URL).clientId("client")
                .signingKey(Fixtures.selfSignedEc());
        assertEquals("ES256", ec.signingAlgorithm("ES256").build().getSigningAlgorithm());

        String names = "is not one of RS256, PS256, ES256, ES384, ES512";
        assertProblem(signingClient().signingAlgorithm("ps256"), "signingAlgorithm 'ps256' " + names);
        assertProblem(signingClient().signingAlgorithm("HS256"), "signingAlgorithm 'HS256' " + names);
        assertProblem(signingClient().signingAlgorithm("ES256"), "signingAlgorithm ES256 needs an EC key; an RSA key signs RS256 or PS256");
        assertProblem(ec.signingAlgorithm("ES384"), "signingAlgorithm ES384 doesn't fit this EC key, which signs ES256");
        assertProblem(ec.signingAlgorithm("PS256"), "signingAlgorithm PS256 doesn't fit this EC key, which signs ES256");
        assertProblem(secretClient().signingAlgorithm("PS256"), "signingAlgorithm is only used with a signingKey");
        assertProblem(secretClient().signingAlgorithm("none"), "signingAlgorithm 'none' " + names);
        // something else pasted here isn't echoed: it may be a secret
        String m = assertThrows(IllegalArgumentException.class,
                () -> signingClient().signingAlgorithm("s3cr3t-value-from-the-vault").build()).getMessage();
        assertTrue(m.contains("signingAlgorithm (not shown) " + names) && !m.contains("s3cr3t"), m);
    }

    @Test
    void theSigningAlgorithmIsShownAndCountsAsACredentialNotATokenSetting() {
        ClientInfo rs = signingClient().build();
        ClientInfo ps = signingClient().signingAlgorithm("PS256").build();
        assertTrue(ps.toString().contains(", signingAlgorithm=PS256"), ps.toString());
        assertFalse(rs.toString().contains("signingAlgorithm"), rs.toString());
        // the token grants the same either way, so it's reused; a failure with one is no reason to wait with the other
        assertEquals(rs.tokenSettings(), ps.tokenSettings());
        assertFalse(rs.credentialsFingerprint().equals(ps.credentialsFingerprint()));
        assertEquals(ps.credentialsFingerprint(), signingClient().signingAlgorithm("PS256").build().credentialsFingerprint());
    }

    @Test
    void theCredentialsFingerprintChangesWithTheCredentialsOnly() {
        String secret = secretClient().build().credentialsFingerprint();
        assertEquals(secret, secretClient().build().credentialsFingerprint()); // the same values built again
        assertEquals(secret, secretClient().scope("other").attribute("note", "x").build().credentialsFingerprint());
        assertFalse(secret.equals(secretClient().clientSecret("fixed").build().credentialsFingerprint()));
        assertFalse(secretClient().build().toString().contains(secret));

        // keys count by their material, so a key read again from the same PEM is the same credential
        String signed = signingClient().build().credentialsFingerprint();
        assertEquals(signed, signingClient().signingKey(Fixtures.rsaKey()).build().credentialsFingerprint());
        assertFalse(signed.equals(signingClient().signingKey(Fixtures.rsaKey().withKeyId("k2")).build().credentialsFingerprint()));
        assertFalse(signed.equals(signingClient().signingKey(Fixtures.clientWithChain()).build().credentialsFingerprint()));
        assertFalse(signed.equals(signingClient().clientCertificate(Fixtures.clientWithChain()).build().credentialsFingerprint()));

        ClientInfo.Builder refresh = secretClient().grant(Grant.REFRESH_TOKEN).subject("jane");
        assertFalse(refresh.refreshToken("r1").build().credentialsFingerprint()
                .equals(refresh.refreshToken("r2").build().credentialsFingerprint()));
        // a secret in one place and a refresh token in the other don't collide
        assertFalse(ClientInfo.global("idp").tokenUrl(TOKEN_URL).clientId("client").clientCertificate(Fixtures.clientWithChain())
                .grant(Grant.REFRESH_TOKEN).subject("jane").refreshToken("secret").build().credentialsFingerprint()
                .equals(ClientInfo.global("idp").tokenUrl(TOKEN_URL).clientId("client").clientSecret("secret")
                        .clientCertificate(Fixtures.clientWithChain()).build().credentialsFingerprint()));
    }

    private static ClientInfo.Builder secretClient() {
        return ClientInfo.global("idp").tokenUrl(TOKEN_URL).clientId("client").clientSecret("secret");
    }

    private static ClientInfo.Builder signingClient() {
        return ClientInfo.global("idp").tokenUrl(TOKEN_URL).grant(Grant.JWT_BEARER).clientId("client")
                .signingKey(Fixtures.rsaKey()).assertionAudience("aud");
    }

    private static void assertProblem(ClientInfo.Builder builder, String problem) {
        String m = assertThrows(IllegalArgumentException.class, builder::build).getMessage();
        assertTrue(m.contains(problem), m);
    }
}
