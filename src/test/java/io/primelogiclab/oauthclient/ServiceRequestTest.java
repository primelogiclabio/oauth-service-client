package io.primelogiclab.oauthclient;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;

import org.junit.jupiter.api.Test;

class ServiceRequestTest {

    private static final String URL = "https://api.example.com/v1/items?key=abc";
    private static final String TOKEN = "eyJhbGciOiJSUzI1NiJ9.e30.c2ln";

    @Test
    void factoriesSetMethodUrlAndBody() {
        assertEquals("GET", ServiceRequest.get(URL).getMethod());
        assertEquals("HEAD", ServiceRequest.head(URL).getMethod());
        assertEquals("DELETE", ServiceRequest.delete(URL).getMethod());
        ServiceRequest post = ServiceRequest.post(URL, "{\"a\":1}");
        assertEquals("POST", post.getMethod());
        assertEquals(URL, post.getUrl());
        assertArrayEquals("{\"a\":1}".getBytes(StandardCharsets.UTF_8), post.getBody());
        assertEquals("PUT", ServiceRequest.put(URL, "x").getMethod());
        assertEquals("OPTIONS", ServiceRequest.of(" options ", URL, null).getMethod());
        assertNull(ServiceRequest.get(URL).getBody());
        assertNull(ServiceRequest.post(URL, null).getBody());
    }

    @Test
    void aTextBodyIsJsonUnlessAContentTypeIsSet() {
        assertEquals(ServiceRequest.DEFAULT_TEXT_TYPE, ServiceRequest.post(URL, "{}").headersToSend().get("Content-Type"));
        assertEquals(ServiceRequest.DEFAULT_BYTES_TYPE,
                ServiceRequest.post(URL, null).body(new byte[] {1, 2}).headersToSend().get("Content-Type"));
        assertEquals("application/xml",
                ServiceRequest.post(URL, "<a/>").contentType("application/xml").headersToSend().get("content-type"));
        assertFalse(ServiceRequest.get(URL).headersToSend().containsKey("Content-Type"));
        // the default isn't one of the caller's headers
        assertTrue(ServiceRequest.post(URL, "{}").getHeaders().isEmpty());
    }

    @Test
    void everyChangeReturnsANewRequest() {
        ServiceRequest base = ServiceRequest.put(URL, "a");
        ServiceRequest withHeader = base.header("Accept", "application/json");
        ServiceRequest withScopes = base.scopes("api");
        assertTrue(base.getHeaders().isEmpty());
        assertTrue(base.getScopes().isEmpty());
        assertEquals("application/json", withHeader.getHeaders().get("accept"));
        assertEquals(Collections.singletonList("api"), withScopes.getScopes());

        byte[] bytes = {1, 2, 3};
        ServiceRequest binary = base.body(bytes);
        bytes[0] = 9;
        byte[] out = binary.getBody();
        out[1] = 9;
        assertArrayEquals(new byte[] {1, 2, 3}, binary.getBody());
    }

    @Test
    void headerNamesAreCaseInsensitiveAndTheLastValueWins() {
        ServiceRequest r = ServiceRequest.get(URL).header("x-trace", "1").header("X-Trace", "2");
        Map<String, String> h = r.getHeaders();
        assertEquals(1, h.size());
        assertEquals("2", h.get("x-trace"));
        assertEquals("X-Trace", h.keySet().iterator().next());
    }

    @Test
    void authorizationAndTheJdksOwnHeadersAreRefused() {
        IllegalArgumentException auth = assertThrows(IllegalArgumentException.class,
                () -> ServiceRequest.get(URL).header("authorization", "Bearer " + TOKEN));
        assertTrue(auth.getMessage().contains("token(...)"), auth.getMessage());
        assertFalse(auth.getMessage().contains(TOKEN));
        for (String name : Arrays.asList("Host", "content-length", "Connection", "Transfer-Encoding")) {
            assertThrows(IllegalArgumentException.class, () -> ServiceRequest.get(URL).header(name, "x"), name);
        }
    }

    @Test
    void badHeaderNamesAndValuesAreRefusedWithoutEchoingTheValue() {
        assertThrows(IllegalArgumentException.class, () -> ServiceRequest.get(URL).header("Bad Name", "x"));
        assertThrows(IllegalArgumentException.class, () -> ServiceRequest.get(URL).header(null, "x"));
        assertThrows(IllegalArgumentException.class, () -> ServiceRequest.get(URL).header("X-A", null));
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> ServiceRequest.get(URL).header("X-Api-Key", "secret-value\r\nX-Evil: 1"));
        assertFalse(e.getMessage().contains("secret-value"), e.getMessage());
    }

    @Test
    void bodyLessMethodsRefuseABody() {
        for (String method : Arrays.asList("GET", "HEAD", "DELETE", "OPTIONS")) {
            assertThrows(IllegalArgumentException.class, () -> ServiceRequest.of(method, URL, "x"), method);
            assertThrows(IllegalArgumentException.class, () -> ServiceRequest.of(method, URL, null).body(new byte[0]), method);
        }
    }

    @Test
    void patchAndUnknownMethodsAreRefused() {
        IllegalArgumentException patch = assertThrows(IllegalArgumentException.class,
                () -> ServiceRequest.of("patch", URL, "{}"));
        assertTrue(patch.getMessage().contains("PATCH"), patch.getMessage());
        assertThrows(IllegalArgumentException.class, () -> ServiceRequest.of("TRACE", URL, null));
        assertThrows(NullPointerException.class, () -> ServiceRequest.of(null, URL, null));
    }

    @Test
    void onlyHttpsUrlsAndNeverEchoed() {
        assertThrows(IllegalArgumentException.class, () -> ServiceRequest.get("http://api.example.com/x"));
        assertThrows(IllegalArgumentException.class, () -> ServiceRequest.get(null));
        assertThrows(IllegalArgumentException.class, () -> ServiceRequest.get("https://api.example.com/x#frag"));
        // a token passed in the URL's place stays out of the message
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> ServiceRequest.get(TOKEN));
        assertFalse(e.getMessage().contains(TOKEN), e.getMessage());
    }

    @Test
    void scopesAreCheckedAndDeduplicated() {
        assertEquals(Arrays.asList("a", "b"), ServiceRequest.get(URL).scopes(" a ", "b", "a").getScopes());
        assertThrows(IllegalArgumentException.class, () -> ServiceRequest.get(URL).scopes("a b"));
        assertThrows(IllegalArgumentException.class, () -> ServiceRequest.get(URL).scopes(" "));
        assertTrue(ServiceRequest.get(URL).scopes("a").scopes().getScopes().isEmpty());
    }

    @Test
    void scopesAndAnOwnTokenDontMix() {
        assertThrows(IllegalArgumentException.class, () -> ServiceRequest.get(URL).scopes("a").token(TOKEN));
        assertThrows(IllegalArgumentException.class, () -> ServiceRequest.get(URL).token(TOKEN).scopes("a"));
    }

    @Test
    void anOwnTokenIsCheckedWithoutEchoingIt() {
        ServiceRequest r = ServiceRequest.get(URL).token(" " + TOKEN + " ");
        assertTrue(r.hasOwnToken());
        assertEquals(TOKEN, r.ownToken());
        assertFalse(ServiceRequest.get(URL).hasOwnToken());
        assertThrows(IllegalArgumentException.class, () -> ServiceRequest.get(URL).token(" "));
        assertThrows(IllegalArgumentException.class, () -> ServiceRequest.get(URL).token(null));
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> ServiceRequest.get(URL).token("abc" + TOKEN + "\r\nX: y"));
        assertFalse(e.getMessage().contains(TOKEN), e.getMessage());
    }

    @Test
    void toStringShowsNeitherQueryNorToken() {
        String s = ServiceRequest.get(URL).token(TOKEN).header("X-Api-Key", "k1").toString();
        assertEquals("GET https://api.example.com/v1/items?...", s);
    }
}
