package io.primelogiclab.oauthclient;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;

import org.junit.jupiter.api.Test;

class PemKeysTest {

    @Test
    void parsesPkcs8AndPkcs1RsaToSameKey() {
        PrivateKey pkcs8 = PemKeys.parsePrivateKey(Fixtures.text("client.key"));
        PrivateKey pkcs1 = PemKeys.parsePrivateKey(Fixtures.text("client-pkcs1.key"));
        assertTrue(pkcs8 instanceof RSAPrivateKey);
        assertEquals(((RSAPrivateKey) pkcs8).getModulus(), ((RSAPrivateKey) pkcs1).getModulus());
        assertArrayEquals(pkcs8.getEncoded(), pkcs1.getEncoded());
    }

    @Test
    void parsesSec1EcKeyAfterEcParametersBlock() {
        PrivateKey ec = PemKeys.parsePrivateKey(Fixtures.text("ec-sec1.key"));
        assertTrue(ec instanceof ECPrivateKey);
        assertEquals(256, ((ECPrivateKey) ec).getParams().getCurve().getField().getFieldSize());
    }

    @Test
    void parsesPkcs8EcKey() {
        assertTrue(PemKeys.parsePrivateKey(Fixtures.text("self-signed-client.key")) instanceof ECPrivateKey);
    }

    @Test
    void rejectsEncryptedGarbageAndTruncatedKeys() {
        assertThrows(IllegalArgumentException.class,
                () -> PemKeys.parsePrivateKey("-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----"));
        assertThrows(IllegalArgumentException.class,
                () -> PemKeys.parsePrivateKey("-----BEGIN PRIVATE KEY-----\nbm90IGEga2V5\n-----END PRIVATE KEY-----"));
        assertThrows(IllegalArgumentException.class,
                () -> PemKeys.parsePrivateKey("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"));
        IllegalArgumentException truncated = assertThrows(IllegalArgumentException.class,
                () -> PemKeys.parsePrivateKey("-----BEGIN EC PRIVATE KEY-----\nMAU=\n-----END EC PRIVATE KEY-----"));
        assertTrue(truncated.getMessage().startsWith("Cannot parse private key"), truncated.getMessage());
    }
}
