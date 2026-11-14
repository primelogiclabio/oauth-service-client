package io.primelogiclab.oauthclient;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Base64;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;

/** TLS socket factories for a client certificate (mutual TLS) and private CAs, with the JDK only. */
final class Tls {

    private Tls() {
    }

    /**
     * @param clientCertificate presented in the handshake, or {@code null} for none
     * @param trustManagers     CAs to trust instead of the JVM's, or {@code null} for the JVM default
     * @throws OAuthServiceException if the JDK can't set up TLS with this key; nothing is sent
     */
    static SSLSocketFactory socketFactory(ClientKey clientCertificate, TrustManager[] trustManagers) {
        try {
            KeyManager[] keyManagers = null;
            if (clientCertificate != null) {
                // the key only lives in this in-memory store, under a random password
                char[] password = randomPassword();
                KeyStore ks = KeyStore.getInstance("PKCS12");
                ks.load(null, null);
                ks.setKeyEntry("client", clientCertificate.getPrivateKey(), password,
                        clientCertificate.getCertificateChain().toArray(new X509Certificate[0]));
                KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
                kmf.init(ks, password);
                keyManagers = kmf.getKeyManagers();
            }
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(keyManagers, trustManagers, null);
            return context.getSocketFactory();
        } catch (GeneralSecurityException | IOException e) {
            throw new OAuthServiceException("Cannot set up TLS" + (clientCertificate == null ? "" : " with " + clientCertificate)
                    + ": " + Strings.safe(e.getMessage()), e);
        }
    }

    private static char[] randomPassword() {
        byte[] b = new byte[16];
        new SecureRandom().nextBytes(b);
        return Base64.getEncoder().encodeToString(b).toCharArray();
    }
}
