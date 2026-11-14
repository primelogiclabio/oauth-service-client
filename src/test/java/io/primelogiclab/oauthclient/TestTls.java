package io.primelogiclab.oauthclient;

import java.security.GeneralSecurityException;
import java.security.KeyStore;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

/** TLS for the stub server and for clients that talk to it, from the fixtures in {@code src/test/resources/tls}. */
final class TestTls {

    private TestTls() {
    }

    /** The server's certificate for localhost; it trusts client certificates the test CA issued. */
    static SSLContext serverContext() {
        try {
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(Fixtures.pkcs12("server.p12"), Fixtures.PASSWORD);
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(kmf.getKeyManagers(), clientTrust(), null);
            return context;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Trusts the test CA only. */
    static TrustManager[] clientTrust() {
        try {
            KeyStore trust = Fixtures.pkcs12("ca-truststore.p12");
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trust);
            return tmf.getTrustManagers();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }
}
