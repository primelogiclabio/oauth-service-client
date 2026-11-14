package io.primelogiclab.oauthclient;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

class AccessTokenTest {

    private static final Instant ISSUED = Instant.parse("2026-11-14T10:00:00Z");

    @Test
    void readsTheStandardFields() {
        AccessToken t = token(response("access_token", "abc", "token_type", "bearer", "expires_in", 3600L,
                "scope", "read write"));
        assertEquals("abc", t.getValue());
        assertEquals("bearer", t.getTokenType());
        assertEquals("Bearer abc", t.toAuthorizationHeader());
        assertEquals("read write", t.getScope());
        assertEquals(Long.valueOf(3600), t.getExpiresIn());
        assertEquals(ISSUED, t.getIssuedAt());
        assertEquals(ISSUED.plusSeconds(3600), t.getExpiresAt());
    }

    @Test
    void tokenTypeDefaultsToBearerAndOtherTypesAreKept() {
        AccessToken plain = token(response("access_token", "abc", "expires_in", 60L));
        assertEquals("Bearer", plain.getTokenType());
        assertEquals("Bearer abc", plain.toAuthorizationHeader());
        assertEquals("DPoP abc", token(response("access_token", "abc", "token_type", "DPoP")).toAuthorizationHeader());
    }

    @Test
    void expiresInAsStringIsRead() {
        assertEquals(ISSUED.plusSeconds(1200), token(response("access_token", "abc", "expires_in", " 1200 ")).getExpiresAt());
    }

    @Test
    void expiresInIsLimitedToZeroAndTenYears() {
        AccessToken negative = token(response("access_token", "abc", "expires_in", -5L));
        assertEquals(Long.valueOf(0), negative.getExpiresIn());
        assertEquals(ISSUED, negative.getExpiresAt());
        AccessToken huge = token(response("access_token", "abc", "expires_in", Long.MAX_VALUE));
        assertEquals(Long.valueOf(AccessToken.MAX_LIFETIME_SECONDS), huge.getExpiresIn());
        assertEquals(ISSUED.plusSeconds(AccessToken.MAX_LIFETIME_SECONDS), huge.getExpiresAt());
    }

    @Test
    void withoutExpiresInTheJwtExpIsUsed() {
        String jwt = jwt("{\"exp\":" + (ISSUED.getEpochSecond() + 7200) + "}");
        AccessToken t = token(response("access_token", jwt));
        assertNull(t.getExpiresIn());
        assertEquals(ISSUED.plusSeconds(7200), t.getExpiresAt());
    }

    @Test
    void theJwtExpWinsOverExpiresIn() {
        String jwt = jwt("{\"exp\":" + (ISSUED.getEpochSecond() + 7200) + "}");
        AccessToken t = token(response("access_token", jwt, "expires_in", 600L));
        assertEquals(ISSUED.plusSeconds(7200), t.getExpiresAt());
        assertEquals(Long.valueOf(600), t.getExpiresIn()); // still reported as sent
    }

    @Test
    void aTokenServerClockAheadOfOursMovesTheExpiryBack() {
        long now = ISSUED.getEpochSecond();
        // the server stamped iat five minutes after we sent the request: its clock runs five minutes ahead
        String jwt = jwt("{\"iat\":" + (now + 300) + ",\"exp\":" + (now + 300 + 3600) + "}");
        assertEquals(ISSUED.plusSeconds(3600), token(response("access_token", jwt, "expires_in", 3600L)).getExpiresAt());
    }

    @Test
    void anIatInThePastLeavesTheExpAlone() {
        long now = ISSUED.getEpochSecond();
        // a token the server issued 50 minutes ago and hands out again: 10 minutes left, not an hour
        String jwt = jwt("{\"iat\":" + (now - 3000) + ",\"exp\":" + (now + 600) + "}");
        assertEquals(ISSUED.plusSeconds(600), token(response("access_token", jwt, "expires_in", 600L)).getExpiresAt());
        String sameSecond = jwt("{\"iat\":" + now + ",\"exp\":" + (now + 600) + "}");
        assertEquals(ISSUED.plusSeconds(600), token(response("access_token", sameSecond)).getExpiresAt());
    }

    @Test
    void anUnusableJwtExpFallsBackToExpiresIn() {
        long now = ISSUED.getEpochSecond();
        // already expired by our clock; iat so far ahead that nothing is left; overflow; no exp
        for (String payload : Arrays.asList("{\"exp\":" + (now - 60) + "}", "{\"exp\":" + now + "}",
                "{\"iat\":" + (now + 7200) + ",\"exp\":" + (now + 3600) + "}",
                "{\"iat\":" + Long.MAX_VALUE + ",\"exp\":" + Long.MIN_VALUE + "}",
                "{\"iat\":" + now + "}")) {
            assertEquals(ISSUED.plusSeconds(900), token(response("access_token", jwt(payload), "expires_in", 900L))
                    .getExpiresAt(), payload);
        }
    }

    @Test
    void withoutJwtExpOrExpiresInTheExpiryIsUnknown() {
        // Salesforce: opaque token, no expires_in
        AccessToken t = token(response("access_token", "00Dxx!opaque", "instance_url", "https://acme.my.salesforce.com"));
        assertNull(t.getExpiresIn());
        assertNull(t.getExpiresAt());
        assertFalse(t.isExpired(ISSUED.plus(Duration.ofDays(365)), Duration.ofMinutes(5)));
        assertTrue(t.toString().contains("expiresAt=unknown"), t.toString());
    }

    @Test
    void anUnusableJwtExpWithoutExpiresInLeavesTheExpiryUnknown() {
        long now = ISSUED.getEpochSecond();
        // exp at or before the send time, not a number, no exp, bad base64, bad JSON
        for (String payload : Arrays.asList("{\"exp\":" + now + "}", "{\"exp\":" + (now - 60) + "}",
                "{\"exp\":\"soon\"}", "{}", "not json")) {
            assertNull(token(response("access_token", jwt(payload))).getExpiresAt(), payload);
        }
        assertNull(token(response("access_token", "a.!!!.c")).getExpiresAt());
        assertNull(token(response("access_token", "a.b.c.d")).getExpiresAt());
    }

    @Test
    void introspectionGivesTheExpiryOfATokenThatHasNone() {
        long now = ISSUED.getEpochSecond();
        AccessToken opaque = token(response("access_token", "00Dxx!opaque", "instance_url", "https://acme.my.salesforce.com"));
        AccessToken t = opaque.withExpiryFrom(response("active", true, "iat", now - 600, "exp", now + 6600));
        assertEquals(ISSUED.plusSeconds(6600), t.getExpiresAt());
        assertEquals("00Dxx!opaque", t.getValue());
        assertEquals("https://acme.my.salesforce.com", t.getField("instance_url"));
        assertEquals(ISSUED, t.getIssuedAt());
        assertNull(opaque.getExpiresAt()); // the original is unchanged
        // the same clock adjustment as for a JWT
        assertEquals(ISSUED.plusSeconds(7200), opaque.withExpiryFrom(response("iat", now + 120, "exp", now + 7320)).getExpiresAt());
    }

    @Test
    void introspectionWithoutAUsableExpChangesNothing() {
        long now = ISSUED.getEpochSecond();
        AccessToken opaque = token(response("access_token", "00Dxx!opaque"));
        assertSame(opaque, opaque.withExpiryFrom(response("active", true)));
        assertSame(opaque, opaque.withExpiryFrom(response("active", true, "exp", now - 1)));
        assertSame(opaque, opaque.withExpiryFrom(response("exp", "soon")));
        assertSame(opaque, opaque.withExpiryFrom(null));
    }

    @Test
    void jwtExpIsLimitedToTenYears() {
        AccessToken t = token(response("access_token", jwt("{\"exp\":" + Long.MAX_VALUE + "}")));
        assertEquals(ISSUED.plusSeconds(AccessToken.MAX_LIFETIME_SECONDS), t.getExpiresAt());
    }

    @Test
    void otherFieldsReachTheCallerWithoutTheToken() {
        AccessToken t = token(response("access_token", "secret-value", "instance_url", "https://acme.my.salesforce.com",
                "id", "https://login.salesforce.com/id/00D/005"));
        assertEquals("https://acme.my.salesforce.com", t.getField("instance_url"));
        assertNull(t.getField("access_token"));
        assertNull(t.getField("missing"));
        assertFalse(t.getFields().containsKey("access_token"));
        assertTrue(t.getFields().containsKey("id"));
    }

    @Test
    void fieldsAreImmutableAndIndependentOfTheResponse() {
        Map<String, Object> nested = new LinkedHashMap<String, Object>();
        nested.put("k", "v");
        List<Object> list = new java.util.ArrayList<Object>(Arrays.<Object>asList("a", nested));
        Map<String, Object> response = response("access_token", "abc", "list", list, "obj", nested);
        AccessToken t = token(response);
        response.put("late", "x");
        list.add("b");
        nested.put("k2", "v2");
        assertNull(t.getField("late"));
        assertEquals(2, ((List<?>) t.getField("list")).size());
        assertEquals(1, ((Map<?, ?>) t.getField("obj")).size());
        assertThrows(UnsupportedOperationException.class, () -> t.getFields().put("x", "y"));
        assertThrows(UnsupportedOperationException.class, () -> ((List<?>) t.getField("list")).clear());
        assertThrows(UnsupportedOperationException.class, () -> ((Map<?, ?>) t.getField("obj")).clear());
        assertThrows(UnsupportedOperationException.class,
                () -> ((Map<?, ?>) ((List<?>) t.getField("list")).get(1)).clear());
    }

    @Test
    void missingAccessTokenIsRejected() {
        assertThrows(IllegalArgumentException.class, () -> token(response("token_type", "Bearer")));
        assertThrows(IllegalArgumentException.class, () -> token(response("access_token", "")));
    }

    @Test
    void toStringNeverShowsTheToken() {
        AccessToken t = token(response("access_token", "secret-value", "expires_in", 60L, "scope", "read",
                "instance_url", "https://acme.my.salesforce.com"));
        String s = t.toString();
        assertFalse(s.contains("secret-value"), s);
        assertTrue(s.contains("scope=read"), s);
        assertTrue(s.contains("fields=[expires_in, scope, instance_url]"), s);
        assertTrue(s.contains("expiresAt=" + ISSUED.plusSeconds(60)), s);
    }

    @Test
    void isExpiredHonoursTheMargin() {
        AccessToken t = token(response("access_token", "abc", "expires_in", 100L));
        assertFalse(t.isExpired(ISSUED.plusSeconds(99), Duration.ZERO));
        assertTrue(t.isExpired(ISSUED.plusSeconds(100), Duration.ZERO));
        assertTrue(t.isExpired(ISSUED.plusSeconds(40), Duration.ofSeconds(60)));
        assertFalse(t.isExpired(ISSUED.plusSeconds(39), Duration.ofSeconds(60)));
    }

    static Map<String, Object> response(Object... keysAndValues) {
        Map<String, Object> m = new LinkedHashMap<String, Object>();
        for (int i = 0; i < keysAndValues.length; i += 2) {
            m.put((String) keysAndValues[i], keysAndValues[i + 1]);
        }
        return m;
    }

    private static AccessToken token(Map<String, Object> response) {
        return AccessToken.fromResponse(response, ISSUED);
    }

    private static String jwt(String payload) {
        Base64.Encoder b64 = Base64.getUrlEncoder().withoutPadding();
        return b64.encodeToString("{\"alg\":\"none\"}".getBytes(StandardCharsets.UTF_8)) + "."
                + b64.encodeToString(payload.getBytes(StandardCharsets.UTF_8)) + ".sig";
    }
}
