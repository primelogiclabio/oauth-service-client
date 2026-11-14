package io.primelogiclab.oauthclient;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * An access token from a service's token endpoint, with the other fields of the response (e.g.
 * Salesforce's {@code instance_url}). Immutable and thread-safe; {@link #toString()} never shows the token.
 */
public final class AccessToken {

    /** Upper bound for a token's lifetime: ten years, so a huge value can't break date arithmetic. */
    static final long MAX_LIFETIME_SECONDS = 10L * 366 * 24 * 3600;

    private final String value;
    private final String tokenType;
    private final String scope;
    private final Long expiresIn;
    private final Instant issuedAt;
    private final Instant expiresAt;
    private final Map<String, Object> fields;

    private AccessToken(String value, String tokenType, String scope, Long expiresIn, Instant issuedAt,
                        Instant expiresAt, Map<String, Object> fields) {
        this.value = value;
        this.tokenType = tokenType;
        this.scope = scope;
        this.expiresIn = expiresIn;
        this.issuedAt = issuedAt;
        this.expiresAt = expiresAt;
        this.fields = fields;
    }

    /**
     * The token from a parsed token response. The expiry comes from the {@code exp} claim when the access
     * token is a JWT, since that is the expiry the service checks; else from {@code expires_in}; else it
     * is unknown (Salesforce) until {@link #withExpiryFrom(Map) introspection} tells.
     *
     * @param issuedAt when the token request was sent, so the expiry errs on the early side
     * @throws IllegalArgumentException if the response has no {@code access_token}
     */
    static AccessToken fromResponse(Map<String, Object> response, Instant issuedAt) {
        String value = string(response.get("access_token"));
        if (value == null || value.isEmpty()) {
            throw new IllegalArgumentException("The token response has no access_token");
        }
        String type = string(response.get("token_type"));
        Long lifetime = number(response.get("expires_in"));
        // a negative or absurdly large value from the server must not break date arithmetic
        Long expiresIn = lifetime == null ? null : Math.max(0L, Math.min(lifetime, MAX_LIFETIME_SECONDS));
        Instant expiresAt = jwtExpiry(value, issuedAt);
        if (expiresAt == null && expiresIn != null) {
            expiresAt = issuedAt.plusSeconds(expiresIn);
        }
        Map<String, Object> fields = new LinkedHashMap<String, Object>(response);
        fields.remove("access_token");
        return new AccessToken(value, type == null ? "Bearer" : type, string(response.get("scope")), expiresIn,
                issuedAt, expiresAt, Collections.unmodifiableMap(deepCopy(fields)));
    }

    /**
     * This token with the expiry from a token introspection response (RFC 7662), whose {@code exp} and
     * {@code iat} mean what they mean in a JWT; this token itself when the response gives no usable {@code exp}.
     */
    AccessToken withExpiryFrom(Map<String, Object> introspection) {
        Instant introspected = claimsExpiry(introspection, issuedAt);
        return introspected == null ? this
                : new AccessToken(value, tokenType, scope, expiresIn, issuedAt, introspected, fields);
    }

    /** The access token itself. */
    public String getValue() {
        return value;
    }

    /** The token type as the server sent it; {@code Bearer} when it sent none. */
    public String getTokenType() {
        return tokenType;
    }

    /** The granted scope as the server sent it, or {@code null}. */
    public String getScope() {
        return scope;
    }

    /** {@code expires_in} as the server sent it (limited to 0 .. ten years), or {@code null} when it sent none. */
    public Long getExpiresIn() {
        return expiresIn;
    }

    /** When the token request was sent. */
    public Instant getIssuedAt() {
        return issuedAt;
    }

    /**
     * When the token expires: from the JWT's {@code exp}, else {@code expires_in}, else introspection;
     * {@code null} when none of them told, and the token is kept until the service rejects it.
     */
    public Instant getExpiresAt() {
        return expiresAt;
    }

    /** One field of the token response, e.g. {@code instance_url}; or {@code null}. */
    public Object getField(String name) {
        return fields.get(name);
    }

    /** Every field of the token response except {@code access_token}; unmodifiable. */
    public Map<String, Object> getFields() {
        return fields;
    }

    /** Value for an {@code Authorization} header, e.g. {@code Bearer eyJ...}. */
    public String toAuthorizationHeader() {
        String type = "bearer".equalsIgnoreCase(tokenType) ? "Bearer" : tokenType;
        return type + " " + value;
    }

    /** True if the token expires at or before {@code now + margin}; never when the expiry is unknown. */
    boolean isExpired(Instant now, Duration margin) {
        return expiresAt != null && !now.plus(margin).isBefore(expiresAt);
    }

    @Override
    public String toString() {
        return "AccessToken{tokenType=" + Strings.safe(tokenType)
                + (scope == null ? "" : ", scope=" + Strings.safe(scope))
                + ", issuedAt=" + issuedAt
                + ", expiresAt=" + (expiresAt == null ? "unknown" : expiresAt)
                + (fields.isEmpty() ? "" : ", fields=" + Strings.safe(fields.keySet().toString()))
                + '}';
    }

    private static String string(Object o) {
        return o == null ? null : o.toString();
    }

    private static Long number(Object o) {
        if (o instanceof Number) {
            return ((Number) o).longValue();
        }
        if (o instanceof String) {
            try {
                return Long.parseLong(((String) o).trim());
            } catch (NumberFormatException ignored) {
                return null;
            }
        }
        return null;
    }

    /** The expiry from the claims of a JWT access token (read, not verified: the service verifies it), or {@code null}. */
    private static Instant jwtExpiry(String token, Instant sent) {
        String[] parts = token.split("\\.", -1);
        if (parts.length != 3) {
            return null;
        }
        try {
            String payload = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
            return claimsExpiry(Json.parseObject(payload), sent);
        } catch (RuntimeException e) {
            return null;
        }
    }

    /**
     * The {@code exp} claim, adjusted for the token server's clock: an {@code iat} later than {@code sent}
     * means that clock runs ahead (plus the response time), so {@code exp} is moved back by the gap. An
     * {@code iat} in the past is left alone, since the server may hand out a token it issued earlier.
     * {@code null} when there's no {@code exp}, or the result is at or before {@code sent}: such a token
     * would look expired the moment it arrives, so the other sources are the better guide.
     */
    private static Instant claimsExpiry(Map<String, Object> claims, Instant sent) {
        try {
            Long exp = number(claims.get("exp"));
            if (exp == null) {
                return null;
            }
            long sentAt = sent.getEpochSecond();
            long expires = exp;
            Long iat = number(claims.get("iat"));
            if (iat != null && iat > sentAt) {
                expires = Math.subtractExact(exp, iat - sentAt);
            }
            if (expires <= sentAt) {
                return null;
            }
            return Instant.ofEpochSecond(Math.min(expires, sentAt + MAX_LIFETIME_SECONDS));
        } catch (RuntimeException e) {
            return null;
        }
    }

    /** Copies nested objects and arrays into unmodifiable ones, so the token stays immutable. */
    private static Map<String, Object> deepCopy(Map<?, ?> map) {
        Map<String, Object> out = new LinkedHashMap<String, Object>();
        for (Map.Entry<?, ?> e : map.entrySet()) {
            out.put(String.valueOf(e.getKey()), deepCopyValue(e.getValue()));
        }
        return out;
    }

    private static Object deepCopyValue(Object v) {
        if (v instanceof Map) {
            return Collections.unmodifiableMap(deepCopy((Map<?, ?>) v));
        }
        if (v instanceof List) {
            List<Object> out = new ArrayList<Object>();
            for (Object o : (List<?>) v) {
                out.add(deepCopyValue(o));
            }
            return Collections.unmodifiableList(out);
        }
        return v;
    }
}
