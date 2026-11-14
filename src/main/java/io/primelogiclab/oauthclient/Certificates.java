package io.primelogiclab.oauthclient;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.Enumeration;
import java.util.List;

/** Certificate helpers with the JDK only (copied from oauth-connector's TlsSupport). */
final class Certificates {

    private Certificates() {
    }

    /** Parses one or more PEM {@code CERTIFICATE} blocks (or DER). */
    static List<X509Certificate> parseCertificates(String pem) {
        try {
            Collection<? extends Certificate> certs = CertificateFactory.getInstance("X.509")
                    .generateCertificates(new ByteArrayInputStream(pem.trim().getBytes(StandardCharsets.US_ASCII)));
            List<X509Certificate> out = new ArrayList<X509Certificate>();
            for (Certificate c : certs) {
                out.add((X509Certificate) c);
            }
            if (out.isEmpty()) {
                throw new IllegalArgumentException("No certificate found in PEM data");
            }
            return out;
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("Cannot parse certificate: " + e.getMessage(), e);
        }
    }

    /** The aliases holding a private key, in the keystore's order. */
    static List<String> keyAliases(KeyStore ks) throws GeneralSecurityException {
        List<String> out = new ArrayList<String>();
        Enumeration<String> aliases = ks.aliases();
        while (aliases.hasMoreElements()) {
            String a = aliases.nextElement();
            if (ks.isKeyEntry(a)) {
                out.add(a);
            }
        }
        return out;
    }

    /** Fails if {@code key} is not the private key for {@code cert}. */
    static void checkKeyMatchesCertificate(PrivateKey key, X509Certificate cert) throws GeneralSecurityException {
        if (!key.getAlgorithm().equalsIgnoreCase(cert.getPublicKey().getAlgorithm())) {
            throw new GeneralSecurityException("the private key (" + key.getAlgorithm() + ") does not belong to the certificate "
                    + cert.getSubjectX500Principal().getName() + " (" + cert.getPublicKey().getAlgorithm() + ")");
        }
        String alg = "EC".equalsIgnoreCase(key.getAlgorithm()) ? "SHA256withECDSA" : "SHA256withRSA";
        byte[] probe = new byte[32];
        new SecureRandom().nextBytes(probe);
        Signature s = Signature.getInstance(alg);
        s.initSign(key);
        s.update(probe);
        byte[] sig = s.sign();
        Signature v = Signature.getInstance(alg);
        v.initVerify(cert.getPublicKey());
        v.update(probe);
        if (!v.verify(sig)) {
            throw new GeneralSecurityException("the private key does not belong to the certificate "
                    + cert.getSubjectX500Principal().getName());
        }
    }

    /** JWS {@code x5t#S256} (and RFC 8705's): base64url SHA-256 of the DER certificate. */
    static String thumbprintS256(X509Certificate cert) {
        return thumbprint("SHA-256", cert);
    }

    /** JWS {@code x5t}: base64url SHA-1 of the DER certificate, which Entra ID's and OIC's examples still use. */
    static String thumbprintSha1(X509Certificate cert) {
        return thumbprint("SHA-1", cert);
    }

    private static String thumbprint(String digest, X509Certificate cert) {
        try {
            byte[] hash = MessageDigest.getInstance(digest).digest(cert.getEncoded());
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }
}
