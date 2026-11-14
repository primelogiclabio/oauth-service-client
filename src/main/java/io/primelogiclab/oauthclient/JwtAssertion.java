package io.primelogiclab.oauthclient;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Signed JWTs for the token request (RFC 7523): the JWT bearer grant's assertion, and the
 * {@code private_key_jwt} client assertion. Each one is short-lived and has a fresh {@code jti}, since
 * Okta, Salesforce and Auth0 accept an assertion only once.
 */
final class JwtAssertion {

    /** The {@code client_assertion_type} of a {@code private_key_jwt} client assertion. */
    static final String CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    /** How long an assertion is valid: Salesforce allows 3 minutes at most, Auth0 5. */
    static final long LIFETIME_SECONDS = 60;

    private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();

    private JwtAssertion() {
    }

    /**
     * The {@code private_key_jwt} client assertion: {@code iss} and {@code sub} are the client ID, {@code aud}
     * the assertion audience, else the token URL (Entra ID, Okta).
     */
    static String clientAssertion(ClientInfo info, String tokenUrl, Instant now) {
        String audience = info.getAssertionAudience() != null ? info.getAssertionAudience() : tokenUrl;
        return create(info, info.getClientId(), audience, now);
    }

    /**
     * The JWT bearer grant's assertion: {@code iss} is the client ID, {@code sub} the subject (a DocuSign user
     * ID, a Salesforce username), else the client ID; {@code aud} the assertion audience.
     */
    static String grantAssertion(ClientInfo info, Instant now) {
        String subject = info.getSubject() != null ? info.getSubject() : info.getClientId();
        return create(info, subject, info.getAssertionAudience(), now);
    }

    private static String create(ClientInfo info, String subject, String audience, Instant now) {
        ClientKey key = info.getSigningKey();
        Jws.Alg alg;
        try {
            alg = Jws.algorithmFor(key.getPrivateKey());
        } catch (IllegalArgumentException e) {
            throw new OAuthServiceException("Cannot sign the assertion: " + e.getMessage(), e);
        }
        Map<String, Object> header = new LinkedHashMap<String, Object>();
        header.put("alg", alg.name());
        header.put("typ", "JWT");
        if (key.getKeyId() != null) {
            header.put("kid", key.getKeyId());
        }
        if (key.hasCertificate()) {
            X509Certificate leaf = key.getCertificateChain().get(0);
            header.put("x5t#S256", Certificates.thumbprintS256(leaf));
            header.put("x5t", Certificates.thumbprintSha1(leaf));
        }
        long iat = now.getEpochSecond();
        Map<String, Object> claims = new LinkedHashMap<String, Object>();
        claims.put("iss", info.getClientId());
        claims.put("sub", subject);
        claims.put("aud", audience);
        claims.put("jti", UUID.randomUUID().toString());
        claims.put("iat", iat);
        claims.put("nbf", iat);
        claims.put("exp", iat + LIFETIME_SECONDS);
        claims.putAll(info.getAssertionClaims()); // ClientInfo keeps the standard claims out of these
        String signingInput = encode(Json.write(header)) + "." + encode(Json.write(claims));
        try {
            byte[] signature = Jws.sign(alg, key.getPrivateKey(), signingInput.getBytes(StandardCharsets.US_ASCII));
            return signingInput + "." + B64.encodeToString(signature);
        } catch (GeneralSecurityException e) {
            throw new OAuthServiceException("Cannot sign the assertion with " + alg + ": "
                    + Strings.safe(e.getMessage()), e);
        }
    }

    private static String encode(String json) {
        return B64.encodeToString(json.getBytes(StandardCharsets.UTF_8));
    }
}
