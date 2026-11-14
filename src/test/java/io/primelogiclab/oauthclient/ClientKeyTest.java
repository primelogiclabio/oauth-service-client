package io.primelogiclab.oauthclient;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;

import org.junit.jupiter.api.Test;

class ClientKeyTest {

    @Test
    void keyOnlyFromPkcs1Pem() {
        ClientKey key = ClientKey.fromPem(Fixtures.text("client-pkcs1.key"));
        assertEquals("RSA", key.getPrivateKey().getAlgorithm());
        assertFalse(key.hasCertificate());
        assertTrue(key.getCertificateChain().isEmpty());
        assertNull(key.getKeyId());
        assertFalse(ClientKey.fromPem(Fixtures.text("client.key"), " ").hasCertificate(), "blank chain PEM means no certificate");
    }

    @Test
    void keyAndChainFromPem() {
        ClientKey key = Fixtures.clientWithChain();
        assertTrue(key.hasCertificate());
        List<X509Certificate> chain = key.getCertificateChain();
        assertEquals(2, chain.size());
        assertTrue(chain.get(0).getSubjectX500Principal().getName().contains("CN=test-client"));
        assertTrue(chain.get(1).getSubjectX500Principal().getName().contains("test CA"));
        assertThrows(UnsupportedOperationException.class, () -> chain.remove(0));
    }

    @Test
    void keyStoreWithAndWithoutAliasGivesTheSameKeyAndChain() throws Exception {
        ClientKey pem = Fixtures.clientWithChain();
        KeyStore p12 = Fixtures.pkcs12("client.p12");
        for (ClientKey fromStore : new ClientKey[] {
                ClientKey.fromKeyStore(p12, Fixtures.PASSWORD),
                ClientKey.fromKeyStore(p12, Fixtures.PASSWORD, "client"),
                ClientKey.fromKeyStore(p12, Fixtures.PASSWORD, " ")}) {
            assertArrayEquals(pem.getPrivateKey().getEncoded(), fromStore.getPrivateKey().getEncoded());
            assertEquals(pem.getCertificateChain(), fromStore.getCertificateChain());
        }
    }

    @Test
    void aliasSelectsTheEntryWhenTheStoreHoldsSeveral() throws Exception {
        ClientKey rsa = Fixtures.clientWithChain();
        ClientKey ec = Fixtures.selfSignedEc();
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry("rsa", rsa.getPrivateKey(), Fixtures.PASSWORD, rsa.getCertificateChain().toArray(new X509Certificate[0]));
        ks.setKeyEntry("ec", ec.getPrivateKey(), Fixtures.PASSWORD, ec.getCertificateChain().toArray(new X509Certificate[0]));
        assertEquals("EC", ClientKey.fromKeyStore(ks, Fixtures.PASSWORD, "ec").getPrivateKey().getAlgorithm());
        assertEquals("RSA", ClientKey.fromKeyStore(ks, Fixtures.PASSWORD, "rsa").getPrivateKey().getAlgorithm());
    }

    @Test
    void rejectsMissingAliasStoreWithoutKeysAndWrongPassword() {
        KeyStore p12 = Fixtures.pkcs12("client.p12");
        IllegalArgumentException alias = assertThrows(IllegalArgumentException.class,
                () -> ClientKey.fromKeyStore(p12, Fixtures.PASSWORD, "nope"));
        assertTrue(alias.getMessage().contains("'nope'"), alias.getMessage());

        IllegalArgumentException noKey = assertThrows(IllegalArgumentException.class,
                () -> ClientKey.fromKeyStore(Fixtures.pkcs12("ca-truststore.p12"), Fixtures.PASSWORD));
        assertTrue(noKey.getMessage().contains("no private key entry"), noKey.getMessage());

        IllegalArgumentException password = assertThrows(IllegalArgumentException.class,
                () -> ClientKey.fromKeyStore(p12, "s3cr3t-wrong".toCharArray()));
        assertTrue(password.getMessage().contains("wrong password"), password.getMessage());
        assertFalse(password.getMessage().contains("s3cr3t-wrong"), password.getMessage());

        assertThrows(IllegalArgumentException.class, () -> ClientKey.fromKeyStore(null, Fixtures.PASSWORD));
    }

    @Test
    void rejectsKeyThatDoesNotBelongToTheCertificate() {
        X509Certificate clientCert = Fixtures.clientWithChain().getCertificateChain().get(0);
        PrivateKey otherRsa = PemKeys.parsePrivateKey(Fixtures.text("server.key"));
        PrivateKey ec = Fixtures.selfSignedEc().getPrivateKey();
        assertThrows(IllegalArgumentException.class, () -> ClientKey.of(otherRsa, clientCert));
        assertThrows(IllegalArgumentException.class, () -> ClientKey.of(ec, clientCert));
        assertThrows(IllegalArgumentException.class,
                () -> ClientKey.fromPem(Fixtures.text("server.key"), Fixtures.text("client.crt")));
    }

    @Test
    void rejectsMissingKeyAndNullCertificates() {
        PrivateKey key = Fixtures.rsaKey().getPrivateKey();
        assertThrows(IllegalArgumentException.class, () -> ClientKey.of(null));
        assertThrows(IllegalArgumentException.class, () -> ClientKey.of(key, (X509Certificate) null));
        assertThrows(IllegalArgumentException.class, () -> ClientKey.fromPem(" "));
        assertFalse(ClientKey.of(key, (X509Certificate[]) null).hasCertificate());
    }

    @Test
    void withKeyIdReturnsACopy() {
        ClientKey key = Fixtures.rsaKey();
        ClientKey withKid = key.withKeyId(" kid-1 ");
        assertEquals("kid-1", withKid.getKeyId());
        assertNull(key.getKeyId());
        assertSame(key.getPrivateKey(), withKid.getPrivateKey());
        assertNull(withKid.withKeyId(" ").getKeyId());
    }

    @Test
    void toStringShowsAlgorithmKidAndSubjectButNoKeyMaterial() {
        ClientKey key = Fixtures.clientWithChain().withKeyId("kid-1");
        String s = key.toString();
        assertTrue(s.contains("RSA key"), s);
        assertTrue(s.contains("kid=kid-1"), s);
        assertTrue(s.contains("CN=test-client"), s);
        String keyBase64 = Base64.getEncoder().encodeToString(key.getPrivateKey().getEncoded());
        for (int i = 0; i + 16 <= keyBase64.length(); i += 16) {
            assertFalse(s.contains(keyBase64.substring(i, i + 16)), s);
        }
        assertTrue(Fixtures.rsaKey().withKeyId("a\nb").toString().contains("kid=a?b"));
    }
}
