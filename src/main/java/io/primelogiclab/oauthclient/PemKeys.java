package io.primelogiclab.oauthclient;

import java.io.ByteArrayOutputStream;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

/**
 * Parses unencrypted PEM private keys without third-party libraries:
 * PKCS#8 ({@code PRIVATE KEY}), PKCS#1 ({@code RSA PRIVATE KEY}) and SEC1 ({@code EC PRIVATE KEY}).
 */
final class PemKeys {

    private static final byte[] RSA_ALGORITHM_ID = {
            0x30, 0x0d, 0x06, 0x09, 0x2a, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00
    };
    private static final byte[] EC_PUBLIC_KEY_OID = {
            0x06, 0x07, 0x2a, (byte) 0x86, 0x48, (byte) 0xce, 0x3d, 0x02, 0x01
    };

    private PemKeys() {
    }

    static PrivateKey parsePrivateKey(String pem) {
        String[] block = privateKeyBlock(pem);
        String type = block[0];
        if (type.contains("ENCRYPTED") || block[1].contains("ENCRYPTED")) {
            throw new IllegalArgumentException("Encrypted private keys are not supported; supply an unencrypted PKCS#8 key or a PrivateKey object");
        }
        byte[] der = decodeBase64(block[2]);
        try {
            if ("RSA PRIVATE KEY".equals(type)) {
                return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(wrapPkcs1(der)));
            }
            if ("EC PRIVATE KEY".equals(type)) {
                return KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(wrapSec1(der)));
            }
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(der);
            for (String alg : new String[] {"RSA", "EC"}) {
                try {
                    return KeyFactory.getInstance(alg).generatePrivate(spec);
                } catch (Exception ignored) {
                    // try next algorithm
                }
            }
            throw new IllegalArgumentException("Unsupported private key: only RSA and EC keys are supported");
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalArgumentException("Cannot parse private key: " + e.getMessage(), e);
        }
    }

    /**
     * The first PEM block whose type ends in {@code PRIVATE KEY}, skipping others such as the
     * {@code EC PARAMETERS} block OpenSSL writes before an EC key: {type, headers, base64 body}.
     * Text without any PEM block is taken as bare base64 PKCS#8.
     */
    private static String[] privateKeyBlock(String pem) {
        if (pem.indexOf("-----BEGIN ") < 0) {
            return new String[] {"PRIVATE KEY", "", pem};
        }
        String type = null;
        StringBuilder headers = new StringBuilder();
        StringBuilder body = new StringBuilder();
        for (String line : pem.split("\\r?\\n")) {
            String l = line.trim();
            if (type == null) {
                if (l.startsWith("-----BEGIN ") && l.endsWith("-----") && l.length() > 16) {
                    String t = l.substring(11, l.length() - 5).trim();
                    if (t.endsWith("PRIVATE KEY")) {
                        type = t;
                    }
                }
            } else if (l.startsWith("-----END ")) {
                return new String[] {type, headers.toString(), body.toString()};
            } else if (l.contains(":")) {
                headers.append(l).append('\n'); // RFC 1421 headers, e.g. Proc-Type: 4,ENCRYPTED
            } else {
                body.append(l);
            }
        }
        throw new IllegalArgumentException(type == null
                ? "No PRIVATE KEY block found in the PEM text" : "Malformed PEM: no END line for " + type);
    }

    private static byte[] decodeBase64(String b64) {
        try {
            return Base64.getMimeDecoder().decode(b64);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Private key is not valid base64", e);
        }
    }

    /** PKCS#8 PrivateKeyInfo { version 0, rsaEncryption, OCTET STRING pkcs1 }. */
    private static byte[] wrapPkcs1(byte[] pkcs1) {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        body.write(0x02);
        body.write(0x01);
        body.write(0x00);
        body.write(RSA_ALGORITHM_ID, 0, RSA_ALGORITHM_ID.length);
        writeTlv(body, 0x04, pkcs1);
        return tlv(0x30, body.toByteArray());
    }

    /** PKCS#8 PrivateKeyInfo { version 0, { ecPublicKey, curve }, OCTET STRING sec1 }. */
    private static byte[] wrapSec1(byte[] sec1) {
        byte[] curveOid = findCurveOid(sec1);
        if (curveOid == null) {
            throw new IllegalArgumentException("EC PRIVATE KEY has no curve parameters; convert it to PKCS#8");
        }
        ByteArrayOutputStream alg = new ByteArrayOutputStream();
        alg.write(EC_PUBLIC_KEY_OID, 0, EC_PUBLIC_KEY_OID.length);
        alg.write(curveOid, 0, curveOid.length);
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        body.write(0x02);
        body.write(0x01);
        body.write(0x00);
        writeTlv(body, 0x30, alg.toByteArray());
        writeTlv(body, 0x04, sec1);
        return tlv(0x30, body.toByteArray());
    }

    /** Returns the full OID TLV inside the [0] parameters element of an ECPrivateKey, or null. */
    private static byte[] findCurveOid(byte[] sec1) {
        int[] seq = readHeader(sec1, 0);          // outer SEQUENCE
        int pos = seq[0];
        int end = seq[0] + seq[1];
        while (pos < end) {
            int tag = sec1[pos] & 0xff;
            int[] h = readHeader(sec1, pos);
            if (tag == 0xa0) {
                int oidStart = h[0];
                int[] oid = readHeader(sec1, oidStart);
                int oidLen = oid[0] - oidStart + oid[1];
                byte[] out = new byte[oidLen];
                System.arraycopy(sec1, oidStart, out, 0, oidLen);
                return out;
            }
            pos = h[0] + h[1];
        }
        return null;
    }

    /** Returns {contentOffset, contentLength} of the TLV at {@code pos}; the content must fit in {@code der}. */
    private static int[] readHeader(byte[] der, int pos) {
        if (pos < 0 || pos + 2 > der.length) {
            throw new IllegalArgumentException("Cannot parse private key: truncated DER");
        }
        int i = pos + 1;
        int len = der[i++] & 0xff;
        if ((len & 0x80) != 0) {
            int n = len & 0x7f;
            if (n == 0 || n > 3 || i + n > der.length) {
                throw new IllegalArgumentException("Cannot parse private key: unsupported DER length");
            }
            len = 0;
            for (int k = 0; k < n; k++) {
                len = (len << 8) | (der[i++] & 0xff);
            }
        }
        if (len > der.length - i) {
            throw new IllegalArgumentException("Cannot parse private key: truncated DER");
        }
        return new int[] {i, len};
    }

    private static byte[] tlv(int tag, byte[] content) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeTlv(out, tag, content);
        return out.toByteArray();
    }

    private static void writeTlv(ByteArrayOutputStream out, int tag, byte[] content) {
        out.write(tag);
        int len = content.length;
        if (len < 0x80) {
            out.write(len);
        } else if (len <= 0xff) {
            out.write(0x81);
            out.write(len);
        } else if (len <= 0xffff) {
            out.write(0x82);
            out.write(len >> 8);
            out.write(len & 0xff);
        } else {
            out.write(0x83);
            out.write(len >> 16);
            out.write((len >> 8) & 0xff);
            out.write(len & 0xff);
        }
        out.write(content, 0, content.length);
    }
}
