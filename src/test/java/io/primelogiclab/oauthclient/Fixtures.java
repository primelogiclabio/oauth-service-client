package io.primelogiclab.oauthclient;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyStore;

/** Loads the throwaway test fixtures from {@code src/test/resources/tls} (see generate.sh there). */
final class Fixtures {

    static final char[] PASSWORD = "changeit".toCharArray();

    private Fixtures() {
    }

    static String text(String name) {
        return new String(bytes(name), StandardCharsets.UTF_8);
    }

    static KeyStore pkcs12(String name) {
        try (InputStream in = open(name)) {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(in, PASSWORD);
            return ks;
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** RSA key without a certificate, as PKCS#1 PEM (the form DocuSign hands out). */
    static ClientKey rsaKey() {
        return ClientKey.fromPem(text("client-pkcs1.key"));
    }

    /** RSA key with its CA-issued certificate chain (client certificate, or a certificate credential). */
    static ClientKey clientWithChain() {
        return ClientKey.fromPem(text("client.key"), text("client-chain.crt"));
    }

    /** Self-signed EC client certificate. */
    static ClientKey selfSignedEc() {
        return ClientKey.fromPem(text("self-signed-client.key"), text("self-signed-client.crt"));
    }

    private static byte[] bytes(String name) {
        try (InputStream in = open(name)) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] b = new byte[4096];
            int n;
            while ((n = in.read(b)) != -1) {
                out.write(b, 0, n);
            }
            return out.toByteArray();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static InputStream open(String name) throws IOException {
        InputStream in = Fixtures.class.getResourceAsStream("/tls/" + name);
        if (in == null) {
            throw new IOException("missing test fixture /tls/" + name + " (run generate.sh in src/test/resources/tls)");
        }
        return in;
    }
}
