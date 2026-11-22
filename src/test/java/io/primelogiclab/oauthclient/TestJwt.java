package io.primelogiclab.oauthclient;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;

/** Reads and verifies the JWTs the library signs, with the JDK only. */
final class TestJwt {

    final Map<String, Object> header;
    final Map<String, Object> claims;
    final String signingInput;
    final byte[] signature;

    private TestJwt(String jwt) {
        String[] parts = jwt.split("\\.", -1);
        if (parts.length != 3) {
            throw new IllegalArgumentException("not a JWS: " + parts.length + " parts");
        }
        header = Json.parseObject(new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8));
        claims = Json.parseObject(new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8));
        signingInput = parts[0] + "." + parts[1];
        signature = Base64.getUrlDecoder().decode(parts[2]);
    }

    static TestJwt parse(String jwt) {
        return new TestJwt(jwt);
    }

    long claim(String name) {
        return ((Number) claims.get(name)).longValue();
    }

    /** True if the signature is valid for {@code key} with the header's algorithm (RS256, PS256 or ES*). */
    boolean verifies(PublicKey key) throws GeneralSecurityException {
        return verifiesAs((String) header.get("alg"), key);
    }

    /** True if the signature is valid for {@code key} with {@code alg}, whatever the header says. */
    boolean verifiesAs(String alg, PublicKey key) throws GeneralSecurityException {
        String jca;
        byte[] sig = signature;
        PSSParameterSpec pss = null;
        if ("RS256".equals(alg)) {
            jca = "SHA256withRSA";
        } else if ("PS256".equals(alg)) {
            jca = "RSASSA-PSS"; // RFC 7518 section 3.5: SHA-256, MGF1 with SHA-256, a 32-byte salt
            pss = new PSSParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"), 32, 1);
        } else if (alg.startsWith("ES")) {
            jca = "SHA" + alg.substring(2) + "withECDSA";
            sig = joseToDer(signature);
        } else {
            throw new IllegalArgumentException("unexpected alg " + alg);
        }
        Signature s = Signature.getInstance(jca);
        if (pss != null) {
            s.setParameter(pss);
        }
        s.initVerify(key);
        s.update(signingInput.getBytes(StandardCharsets.US_ASCII));
        return s.verify(sig);
    }

    /** Fixed-width {@code r || s} to DER, as the JCA expects. */
    static byte[] joseToDer(byte[] jose) {
        int half = jose.length / 2;
        byte[] r = new BigInteger(1, Arrays.copyOfRange(jose, 0, half)).toByteArray();
        byte[] s = new BigInteger(1, Arrays.copyOfRange(jose, half, jose.length)).toByteArray();
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        writeTlv(body, 0x02, r);
        writeTlv(body, 0x02, s);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeTlv(out, 0x30, body.toByteArray());
        return out.toByteArray();
    }

    private static void writeTlv(ByteArrayOutputStream out, int tag, byte[] content) {
        out.write(tag);
        if (content.length < 0x80) {
            out.write(content.length);
        } else {
            out.write(0x81);
            out.write(content.length);
        }
        out.write(content, 0, content.length);
    }
}
