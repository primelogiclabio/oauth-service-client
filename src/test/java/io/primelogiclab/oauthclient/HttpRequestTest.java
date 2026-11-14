package io.primelogiclab.oauthclient;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class HttpRequestTest {

    @Test
    void redactUrlHidesQueryUserInfoAndFragment() {
        assertEquals("https://api.example.com/v1/items?...", HttpRequest.redactUrl("https://api.example.com/v1/items?key=s3cr3t"));
        assertEquals("https://api.example.com/x?...", HttpRequest.redactUrl("https://api.example.com/x#frag"));
        assertEquals("https://host/x", HttpRequest.redactUrl("https://user:pw@host/x"));
        assertEquals("https://host/x?...", HttpRequest.redactUrl("https://user:p@ss@host/x?y=1"));
        assertEquals("https://...@host/x", HttpRequest.redactUrl("https://user:pa/ss@host/x"));
        assertEquals("https://host/x", HttpRequest.redactUrl("https://user:pa?ss@host/x"));
        assertEquals("https://host?...", HttpRequest.redactUrl("https://user:pw@host?x=1"));
    }

    @Test
    void anAtSignInTheQueryNeverExposesTheRestOfIt() {
        // no path before the query
        assertEquals("https://api.example.com?...",
                HttpRequest.redactUrl("https://api.example.com?user=a@x.com&api_key=SECRET"));
        assertEquals("https://api.example.com:8443?...",
                HttpRequest.redactUrl("https://api.example.com:8443?user=a@x.com&api_key=SECRET"));
        // a path, and a slash or an at sign inside the query
        assertEquals("https://host/p?...", HttpRequest.redactUrl("https://host/p?mail=a@b&key=SECRET"));
        assertEquals("https://host?...", HttpRequest.redactUrl("https://host?a=/b@SECRET"));
        assertEquals("https://host?...", HttpRequest.redactUrl("https://host?redirect=a@b/SECRET"));
    }

    @Test
    void redactUrlReplacesControlCharacters() {
        assertEquals("https://host/a?...", HttpRequest.redactUrl("https://host/a\nb"));
    }
}
