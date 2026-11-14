package io.primelogiclab.oauthclient;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

class JsonTest {

    @Test
    void parsesNestedDocument() {
        Map<String, Object> m = Json.parseObject(
                "{ \"a\": \"x\\\"y\\u00e9\\n\", \"n\": 42, \"big\": 12345678901234567890, \"d\": -1.5e2,"
                        + " \"t\": true, \"f\": false, \"z\": null, \"arr\": [1, \"two\", {\"k\": []}] }");
        assertEquals("x\"yé\n", m.get("a"));
        assertEquals(42L, m.get("n"));
        assertTrue(m.get("big") instanceof Double);
        assertEquals(-150.0, m.get("d"));
        assertEquals(Boolean.TRUE, m.get("t"));
        assertEquals(Boolean.FALSE, m.get("f"));
        assertTrue(m.containsKey("z"));
        assertNull(m.get("z"));
        List<?> arr = (List<?>) m.get("arr");
        assertEquals(3, arr.size());
        assertEquals("two", arr.get(1));
    }

    @Test
    void roundTrips() {
        Map<String, Object> m = new LinkedHashMap<String, Object>();
        m.put("s", "quote\" back\\ ctl\u0001");
        m.put("n", 7L);
        m.put("l", Arrays.asList("a", 1L, null));
        assertEquals(m, Json.parseObject(Json.write(m)));
    }

    @Test
    void rejectsMalformedInput() {
        assertThrows(IllegalArgumentException.class, () -> Json.parse("{\"a\":1,}"));
        assertThrows(IllegalArgumentException.class, () -> Json.parse("{\"a\" 1}"));
        assertThrows(IllegalArgumentException.class, () -> Json.parse("[1 2]"));
        assertThrows(IllegalArgumentException.class, () -> Json.parse("\"unterminated"));
        assertThrows(IllegalArgumentException.class, () -> Json.parse("{} extra"));
        assertThrows(IllegalArgumentException.class, () -> Json.parseObject("[1]"));
        StringBuilder deep = new StringBuilder();
        for (int i = 0; i < 100; i++) deep.append('[');
        assertThrows(IllegalArgumentException.class, () -> Json.parse(deep.toString()));
    }
}
