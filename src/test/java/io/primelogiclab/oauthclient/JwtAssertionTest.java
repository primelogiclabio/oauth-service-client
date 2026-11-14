package io.primelogiclab.oauthclient;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Base64;

import org.junit.jupiter.api.Test;

class JwtAssertionTest {

    private static final Instant NOW = Instant.parse("2026-11-14T10:00:00Z");
    private static final String TOKEN_URL = "https://idp.example.com/oauth2/token";

    @Test
    void grantAssertionHasTheStandardClaimsAndTheCallersOnes() throws Exception {
        ClientInfo info = ClientInfo.forTenant("docusign", "acme").tokenUrl(TOKEN_URL).grant(Grant.JWT_BEARER)
                .clientId("integration-key").signingKey(Fixtures.rsaKey().withKeyId("k1")).subject("user-guid")
                .assertionAudience("account-d.docusign.com").assertionClaim("scope", "signature impersonation").build();
        TestJwt jwt = TestJwt.parse(JwtAssertion.grantAssertion(info, NOW));

        assertEquals("RS256", jwt.header.get("alg"));
        assertEquals("JWT", jwt.header.get("typ"));
        assertEquals("k1", jwt.header.get("kid"));
        assertFalse(jwt.header.containsKey("x5t"), "no certificate, no thumbprint");
        assertFalse(jwt.header.containsKey("x5t#S256"));
        assertEquals("integration-key", jwt.claims.get("iss"));
        assertEquals("user-guid", jwt.claims.get("sub"));
        assertEquals("account-d.docusign.com", jwt.claims.get("aud"));
        assertEquals("signature impersonation", jwt.claims.get("scope"));
        assertEquals(NOW.getEpochSecond(), jwt.claim("iat"));
        assertEquals(NOW.getEpochSecond(), jwt.claim("nbf"));
        assertEquals(60, jwt.claim("exp") - jwt.claim("iat"));
        // client-pkcs1.key is client.key in PKCS#1 form, so the client certificate holds its public key
        assertTrue(jwt.verifies(clientCertificate().getPublicKey()));
    }

    @Test
    void grantAssertionSubjectDefaultsToTheClientId() {
        ClientInfo info = ClientInfo.global("oic").tokenUrl(TOKEN_URL).grant(Grant.JWT_BEARER).clientId("app")
                .signingKey(Fixtures.rsaKey()).assertionAudience("https://identity.oraclecloud.com/").build();
        assertEquals("app", TestJwt.parse(JwtAssertion.grantAssertion(info, NOW)).claims.get("sub"));
    }

    @Test
    void clientAssertionWithACertificateCarriesItsThumbprints() throws Exception {
        ClientKey key = Fixtures.clientWithChain();
        ClientInfo info = ClientInfo.global("graph").tokenUrl(TOKEN_URL).clientId("app-id").signingKey(key).build();
        TestJwt jwt = TestJwt.parse(JwtAssertion.clientAssertion(info, TOKEN_URL, NOW));

        X509Certificate leaf = key.getCertificateChain().get(0);
        assertEquals(thumbprint("SHA-256", leaf), jwt.header.get("x5t#S256"));
        assertEquals(thumbprint("SHA-1", leaf), jwt.header.get("x5t"));
        assertFalse(jwt.header.containsKey("kid"));
        assertEquals("app-id", jwt.claims.get("iss"));
        assertEquals("app-id", jwt.claims.get("sub"));
        assertEquals(TOKEN_URL, jwt.claims.get("aud"), "the audience defaults to the token URL");
        assertTrue(jwt.verifies(leaf.getPublicKey()));
    }

    @Test
    void clientAssertionTakesTheAssertionAudience() {
        ClientInfo info = ClientInfo.global("auth0").tokenUrl(TOKEN_URL).clientId("app").signingKey(Fixtures.rsaKey())
                .assertionAudience("https://tenant.auth0.com/").build();
        assertEquals("https://tenant.auth0.com/",
                TestJwt.parse(JwtAssertion.clientAssertion(info, TOKEN_URL, NOW)).claims.get("aud"));
    }

    @Test
    void ecKeysSignWithTheirCurvesAlgorithm() throws Exception {
        ClientKey key = Fixtures.selfSignedEc();
        ClientInfo info = ClientInfo.global("okta").tokenUrl(TOKEN_URL).clientId("app").signingKey(key).build();
        TestJwt jwt = TestJwt.parse(JwtAssertion.clientAssertion(info, TOKEN_URL, NOW));
        assertEquals("ES256", jwt.header.get("alg"));
        assertEquals(64, jwt.signature.length, "JWS wants r || s, not DER");
        assertTrue(jwt.verifies(key.getCertificateChain().get(0).getPublicKey()));
    }

    @Test
    void everyAssertionHasItsOwnJti() {
        ClientInfo info = ClientInfo.global("okta").tokenUrl(TOKEN_URL).clientId("app").signingKey(Fixtures.rsaKey()).build();
        Object first = TestJwt.parse(JwtAssertion.clientAssertion(info, TOKEN_URL, NOW)).claims.get("jti");
        Object second = TestJwt.parse(JwtAssertion.clientAssertion(info, TOKEN_URL, NOW)).claims.get("jti");
        assertNotEquals(first, second);
    }

    @Test
    void aWeakRsaKeyIsRejectedWhenTheClientInfoIsBuilt() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(1024);
        ClientKey weak = ClientKey.of(gen.generateKeyPair().getPrivate());
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> ClientInfo.global("okta")
                .tokenUrl(TOKEN_URL).clientId("app").signingKey(weak).build());
        assertTrue(e.getMessage().contains("signingKey can't sign: RSA key has 1024 bits; at least 2048"), e.getMessage());
    }

    @Test
    void aSignatureThatIsNotDerIsRefusedCleanly() {
        byte[] raw = new byte[64]; // r and s side by side, as some HSM providers return them
        raw[0] = 0x12;
        assertThrows(IllegalArgumentException.class, () -> Jws.derToJose(raw, 32));
        byte[] truncated = {0x30, 0x44, 0x02, 0x20, 1, 2, 3, 4};
        assertThrows(IllegalArgumentException.class, () -> Jws.derToJose(truncated, 32));
        byte[] badLength = {0x30, 0x06, 0x02, 0x7f, 1, 0x02, 0x01, 1};
        assertThrows(IllegalArgumentException.class, () -> Jws.derToJose(badLength, 32));
        byte[] trailing = {0x30, 0x06, 0x02, 0x01, 1, 0x02, 0x01, 1, 9};
        assertThrows(IllegalArgumentException.class, () -> Jws.derToJose(trailing, 32));
        byte[] ok = {0x30, 0x06, 0x02, 0x01, 1, 0x02, 0x01, 2};
        byte[] jose = Jws.derToJose(ok, 32);
        assertEquals(1, jose[31]);
        assertEquals(2, jose[63]);
    }

    private static X509Certificate clientCertificate() {
        return Fixtures.clientWithChain().getCertificateChain().get(0);
    }

    private static String thumbprint(String digest, X509Certificate cert) throws Exception {
        byte[] hash = MessageDigest.getInstance(digest).digest(cert.getEncoded());
        return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
    }
}
