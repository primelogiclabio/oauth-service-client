package io.primelogiclab.oauthclient;

import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * A client's private key, with its certificate chain (leaf first) when it has one and an optional key
 * ID. {@link ClientInfo} uses it in two ways: as the signing key for JWTs (the JWT bearer grant's
 * assertion, or a {@code private_key_jwt} client assertion) and as the client certificate for mutual
 * TLS. Immutable and thread-safe; every factory checks the key against the leaf certificate at once.
 */
public final class ClientKey {

    private final PrivateKey privateKey;
    private final List<X509Certificate> certificateChain;
    private final String keyId;

    private ClientKey(PrivateKey privateKey, List<X509Certificate> certificateChain, String keyId) {
        this.privateKey = privateKey;
        this.certificateChain = certificateChain;
        this.keyId = keyId;
    }

    /**
     * @param key   the private key (RSA or EC)
     * @param chain the certificate chain, leaf first; may be empty when the key has no certificate
     * @throws IllegalArgumentException if the key is missing or doesn't belong to the leaf certificate
     */
    public static ClientKey of(PrivateKey key, X509Certificate... chain) {
        if (key == null) {
            throw new IllegalArgumentException("private key is required");
        }
        List<X509Certificate> certs = new ArrayList<X509Certificate>();
        if (chain != null) {
            for (X509Certificate c : chain) {
                if (c == null) {
                    throw new IllegalArgumentException("certificate chain must not contain null");
                }
                certs.add(c);
            }
        }
        if (!certs.isEmpty()) {
            try {
                Certificates.checkKeyMatchesCertificate(key, certs.get(0));
            } catch (GeneralSecurityException e) {
                throw new IllegalArgumentException("Cannot use this client key: " + Strings.safe(e.getMessage()), e);
            }
        }
        return new ClientKey(key, Collections.unmodifiableList(certs), null);
    }

    /**
     * A key without a certificate, from unencrypted PEM text (PKCS#8 {@code PRIVATE KEY}, PKCS#1
     * {@code RSA PRIVATE KEY} or SEC1 {@code EC PRIVATE KEY}).
     */
    public static ClientKey fromPem(String keyPem) {
        return fromPem(keyPem, null);
    }

    /**
     * A key and its certificate chain from PEM text, e.g. {@code tls.key} and {@code tls.crt}.
     *
     * @param keyPem              unencrypted private key (PKCS#8, PKCS#1 or SEC1)
     * @param certificateChainPem one or more {@code CERTIFICATE} blocks, leaf first; blank for none
     */
    public static ClientKey fromPem(String keyPem, String certificateChainPem) {
        if (Strings.isBlank(keyPem)) {
            throw new IllegalArgumentException("private key PEM is required");
        }
        PrivateKey key = PemKeys.parsePrivateKey(keyPem);
        if (Strings.isBlank(certificateChainPem)) {
            return of(key);
        }
        List<X509Certificate> chain = Certificates.parseCertificates(certificateChainPem);
        return of(key, chain.toArray(new X509Certificate[0]));
    }

    /** The first private key entry of a loaded keystore (PKCS#12 or JKS), with its certificate chain. */
    public static ClientKey fromKeyStore(KeyStore keyStore, char[] password) {
        return fromKeyStore(keyStore, password, null);
    }

    /**
     * A private key entry of a loaded keystore (PKCS#12 or JKS), with its certificate chain. The
     * keystore and password are only read here, not kept.
     *
     * @param password the entry's password (for PKCS#12 usually the store password)
     * @param alias    the entry to use; blank for the first private key entry
     */
    public static ClientKey fromKeyStore(KeyStore keyStore, char[] password, String alias) {
        if (keyStore == null) {
            throw new IllegalArgumentException("keystore is required");
        }
        String a = Strings.trim(alias);
        try {
            if (a == null) {
                a = Certificates.firstKeyAlias(keyStore);
                if (a == null) {
                    throw new IllegalArgumentException("keystore has no private key entry");
                }
            } else if (!keyStore.isKeyEntry(a)) {
                throw new IllegalArgumentException("keystore has no private key entry '" + Strings.safe(a) + "'");
            }
            Key key = keyStore.getKey(a, password == null ? new char[0] : password);
            if (!(key instanceof PrivateKey)) {
                throw new IllegalArgumentException("keystore entry '" + Strings.safe(a) + "' is not a private key");
            }
            Certificate[] certs = keyStore.getCertificateChain(a);
            List<X509Certificate> chain = new ArrayList<X509Certificate>();
            if (certs != null) {
                for (Certificate c : certs) {
                    if (!(c instanceof X509Certificate)) {
                        throw new IllegalArgumentException("keystore entry '" + Strings.safe(a) + "' has a non-X.509 certificate");
                    }
                    chain.add((X509Certificate) c);
                }
            }
            return of((PrivateKey) key, chain.toArray(new X509Certificate[0]));
        } catch (UnrecoverableKeyException e) {
            throw new IllegalArgumentException("Cannot read keystore entry '" + Strings.safe(a) + "': wrong password", e);
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("Cannot read keystore: " + Strings.safe(e.getMessage()), e);
        }
    }

    /** A copy with the key ID sent as the JWT {@code kid} header (e.g. the key's ID registered at Okta); blank for none. */
    public ClientKey withKeyId(String keyId) {
        return new ClientKey(privateKey, certificateChain, Strings.trim(keyId));
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    /** Leaf first; empty when the key has no certificate. */
    public List<X509Certificate> getCertificateChain() {
        return certificateChain;
    }

    public boolean hasCertificate() {
        return !certificateChain.isEmpty();
    }

    /** The JWT {@code kid} header, or {@code null}. */
    public String getKeyId() {
        return keyId;
    }

    /** Key algorithm, key ID and certificate subject; never key material. */
    @Override
    public String toString() {
        return "ClientKey{" + privateKey.getAlgorithm() + " key"
                + (keyId == null ? "" : ", kid=" + Strings.safe(keyId))
                + (certificateChain.isEmpty() ? ""
                        : ", certificate=" + Strings.safe(certificateChain.get(0).getSubjectX500Principal().getName()))
                + '}';
    }
}
