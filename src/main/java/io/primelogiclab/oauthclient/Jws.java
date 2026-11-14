package io.primelogiclab.oauthclient;

import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;

/** JWS signing on top of the JDK's JCA providers (the signing half of oauth-connector's Jws). */
final class Jws {

    /** Smallest RSA key accepted for signing. */
    static final int MIN_RSA_KEY_BITS = 2048;

    /** The algorithms the library signs with: RS256 for RSA keys, ES256/384/512 by the EC key's curve. */
    enum Alg {
        RS256("SHA256withRSA", 0), ES256("SHA256withECDSA", 32), ES384("SHA384withECDSA", 48), ES512("SHA512withECDSA", 66);

        final String jcaName;
        final int ecCoordinateSize;

        Alg(String jcaName, int ecCoordinateSize) {
            this.jcaName = jcaName;
            this.ecCoordinateSize = ecCoordinateSize;
        }

        boolean isEc() {
            return ecCoordinateSize > 0;
        }
    }

    private Jws() {
    }

    /**
     * The algorithm for {@code key}: RS256 for RSA, ES256, ES384 or ES512 for an EC key on P-256, P-384 or P-521.
     *
     * @throws IllegalArgumentException with {@link #signingKeyProblem(PrivateKey)}'s reason
     */
    static Alg algorithmFor(PrivateKey key) {
        String problem = signingKeyProblem(key);
        if (problem != null) {
            throw new IllegalArgumentException(problem);
        }
        return key instanceof ECKey ? ecAlgorithm(((ECKey) key).getParams()) : Alg.RS256;
    }

    /**
     * Why {@code key} can't sign, or {@code null} if it can: RSA keys need at least {@link #MIN_RSA_KEY_BITS}
     * bits, EC keys a NIST curve (P-256, P-384, P-521). An RSA key held in an HSM or the Windows certificate
     * store may not reveal its size and is accepted; such an EC key is not, since its curve decides the algorithm.
     */
    static String signingKeyProblem(PrivateKey key) {
        if (key instanceof RSAKey) {
            int bits = ((RSAKey) key).getModulus().bitLength();
            return bits < MIN_RSA_KEY_BITS
                    ? "RSA key has " + bits + " bits; at least " + MIN_RSA_KEY_BITS + " are required" : null;
        }
        if (key instanceof ECKey) {
            return ecAlgorithm(((ECKey) key).getParams()) == null ? "EC key is not on P-256, P-384 or P-521" : null;
        }
        if ("RSA".equalsIgnoreCase(key.getAlgorithm())) {
            return null;
        }
        if ("EC".equalsIgnoreCase(key.getAlgorithm())) {
            return "this EC key doesn't reveal its curve, which decides the signing algorithm";
        }
        return "unsupported key algorithm " + Strings.safe(key.getAlgorithm()) + " (RSA and EC are supported)";
    }

    /** Signs {@code input}; an ECDSA signature comes back as JWS wants it, fixed-width {@code r || s}. */
    static byte[] sign(Alg alg, PrivateKey key, byte[] input) throws GeneralSecurityException {
        Signature sig;
        try {
            sig = Signature.getInstance(alg.jcaName);
        } catch (NoSuchAlgorithmException e) {
            throw new NoSuchAlgorithmException(alg + " is not supported by this Java runtime", e);
        }
        sig.initSign(key);
        sig.update(input);
        byte[] raw = sig.sign();
        return alg.isEc() ? derToJose(raw, alg.ecCoordinateSize) : raw;
    }

    /**
     * The ES algorithm for a key on one of the NIST curves JWS uses, or {@code null} for any other curve,
     * compared by the curve itself, not just its size.
     */
    static Alg ecAlgorithm(ECParameterSpec params) {
        String[][] curves = {{"secp256r1", "ES256"}, {"secp384r1", "ES384"}, {"secp521r1", "ES512"}};
        for (String[] c : curves) {
            try {
                AlgorithmParameters ap = AlgorithmParameters.getInstance("EC");
                ap.init(new ECGenParameterSpec(c[0]));
                ECParameterSpec std = ap.getParameterSpec(ECParameterSpec.class);
                if (std.getOrder().equals(params.getOrder()) && std.getCurve().equals(params.getCurve())
                        && std.getGenerator().equals(params.getGenerator())) {
                    return Alg.valueOf(c[1]);
                }
            } catch (GeneralSecurityException e) {
                // curve not available in this runtime: can't be the key's curve
            }
        }
        return null;
    }

    /** DER {@code SEQUENCE { INTEGER r, INTEGER s }} to fixed-width {@code r || s}. */
    static byte[] derToJose(byte[] der, int size) {
        int pos = 1;
        int seqLen = der[pos++] & 0xff;
        if ((seqLen & 0x80) != 0) {
            pos += seqLen & 0x7f;
        }
        byte[] out = new byte[size * 2];
        for (int part = 0; part < 2; part++) {
            if (der[pos++] != 0x02) {
                throw new IllegalArgumentException("Invalid ECDSA signature");
            }
            int len = der[pos++] & 0xff;
            int start = pos;
            int n = len;
            while (n > size && der[start] == 0) { // strip sign padding
                start++;
                n--;
            }
            if (n > size) {
                throw new IllegalArgumentException("Invalid ECDSA signature length");
            }
            System.arraycopy(der, start, out, part * size + (size - n), n);
            pos += len;
        }
        return out;
    }
}
