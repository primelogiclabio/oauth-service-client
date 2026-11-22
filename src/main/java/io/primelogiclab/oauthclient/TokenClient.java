package io.primelogiclab.oauthclient;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.Supplier;

/**
 * Gets tokens from a service's token endpoint with the grant and client authentication the {@link ClientInfo}
 * gives. A token request is sent again only when the server certainly didn't process it (no connection,
 * 429, or 503 with Retry-After), since some vendors cap token requests and a resent rotating refresh token
 * can revoke the whole token family. Thread-safe.
 */
final class TokenClient implements TokenFetcher {

    static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(10);
    static final Duration READ_TIMEOUT = Duration.ofSeconds(30);
    /** Longest one token request may take, with all its attempts and the pauses between them. */
    static final Duration CALL_TIMEOUT = UrlConnectionTransport.DEFAULT_REQUEST_TIMEOUT;
    static final int MAX_RETRIES = 2;
    static final Duration RETRY_BACKOFF = Duration.ofMillis(500);

    /** Largest token response accepted, in characters; real ones are a few kilobytes. */
    static final int MAX_RESPONSE_CHARS = 256 * 1024;
    /** Largest token response read from the connection, in bytes. */
    static final int MAX_RESPONSE_BYTES = 1024 * 1024;
    /** Most characters of a non-OAuth error body put in an exception message. */
    private static final int MAX_ERROR_BODY = 500;
    /** Sent credentials shorter than this aren't removed from the server's text: they'd mangle it, and real ones are longer. */
    private static final int MIN_SCRUB_LENGTH = 8;
    /** Form fields that carry a credential. */
    private static final List<String> CREDENTIAL_FIELDS =
            Arrays.asList("client_secret", "refresh_token", "assertion", "client_assertion");

    private final HttpExecutor http;
    private final Clock clock;
    private final MetadataCache metadata;

    /** With the JVM-wide server metadata. */
    TokenClient(HttpExecutor http, Clock clock) {
        this(http, clock, MetadataCache.SHARED);
    }

    TokenClient(HttpExecutor http, Clock clock, MetadataCache metadata) {
        this.http = http;
        this.clock = clock;
        this.metadata = metadata;
    }

    /** With the JVM's trust store and the default timeouts and retries. */
    static TokenClient withDefaults() {
        HttpTransport transport = new UrlConnectionTransport(CONNECT_TIMEOUT, READ_TIMEOUT, CALL_TIMEOUT, null);
        return new TokenClient(new HttpExecutor(transport, MAX_RETRIES, RETRY_BACKOFF, HttpExecutor.THREAD_SLEEPER,
                CALL_TIMEOUT), Clock.systemUTC());
    }

    /**
     * @throws OAuthServiceException when no token could be had: the request failed without an answer, the
     *         server answered with an error (its OAuth {@code error} is on the exception), or the answer isn't a token
     */
    @Override
    public AccessToken fetch(final ClientInfo info, final List<String> scopes) {
        final Instant[] sentAt = new Instant[1];
        // every credential sent, so an error text that echoes the request can be cleaned of them
        final List<String> sent = new ArrayList<String>(Arrays.asList(info.getClientSecret(), info.getRefreshToken()));
        try {
            final Endpoint endpoint = endpoint(info);
            HttpResponse response = http.execute(new Supplier<HttpRequest>() {
                @Override
                public HttpRequest get() {
                    // built anew for every attempt: an assertion's jti may be used only once
                    Instant now = clock.instant();
                    HttpRequest request = tokenRequest(info, scopes, endpoint.url, endpoint.authentication, now);
                    sentAt[0] = now;
                    sent.addAll(credentialsIn(request));
                    // sent at most once by the JDK: it would otherwise resend a POST whose connection failed
                    // before the answer, reusing a one-time assertion or refresh token and counting against
                    // vendor caps; the library's own retries above happen only when the server didn't get it
                    return request.notResendable().withMaxResponseBytes(MAX_RESPONSE_BYTES);
                }
            }, HttpExecutor.Retry.IF_NOT_PROCESSED);
            return parse(response, sentAt[0], sent, clock);
        } catch (OAuthServiceException e) {
            throw new OAuthServiceException("Token request for " + info.label() + " failed: " + e.getMessage(),
                    e.getError(), e.getErrorDescription(), e.getErrorUri(), e.getHttpStatus(), e.retryAfter(), e);
        }
    }

    /**
     * The token endpoint and how to authenticate there: the client info's token URL and client authentication;
     * or, from the server's metadata, its token endpoint (the mutual TLS alias for a client with a certificate)
     * and the secret method it lists.
     */
    private Endpoint endpoint(ClientInfo info) {
        if (info.getTokenUrl() != null) {
            return new Endpoint(info.getTokenUrl(), info.clientAuthentication());
        }
        ServerMetadata server = metadata.resolve(info, http);
        String url = info.getClientCertificate() != null && server.mtlsTokenEndpoint() != null
                ? server.mtlsTokenEndpoint() : server.tokenEndpoint();
        return new Endpoint(url, listedAuthentication(info.clientAuthentication(), server.tokenEndpointAuthMethods()));
    }

    /**
     * {@code configured}, unless it is a secret method the server leaves out of the methods it lists while it
     * lists the other one: then that one. Nothing else is adapted, and a server that lists none (RFC 8414's
     * default, {@code client_secret_basic}) gets what is configured.
     */
    static ClientInfo.ClientAuthentication listedAuthentication(ClientInfo.ClientAuthentication configured,
                                                                List<String> listed) {
        if (listed.isEmpty()) {
            return configured;
        }
        if (configured == ClientInfo.ClientAuthentication.CLIENT_SECRET_BASIC
                && !listed.contains("client_secret_basic") && listed.contains("client_secret_post")) {
            return ClientInfo.ClientAuthentication.CLIENT_SECRET_POST;
        }
        if (configured == ClientInfo.ClientAuthentication.CLIENT_SECRET_POST
                && !listed.contains("client_secret_post") && listed.contains("client_secret_basic")) {
            return ClientInfo.ClientAuthentication.CLIENT_SECRET_BASIC;
        }
        return configured;
    }

    /** The token request with the client info's own token URL and client authentication. */
    static HttpRequest tokenRequest(ClientInfo info, List<String> scopes, String tokenUrl, Instant now) {
        return tokenRequest(info, scopes, tokenUrl, info.clientAuthentication(), now);
    }

    /** The token request: grant fields, scope, token parameters, then the client authentication. */
    static HttpRequest tokenRequest(ClientInfo info, List<String> scopes, String tokenUrl,
                                    ClientInfo.ClientAuthentication authentication, Instant now) {
        List<String[]> form = new ArrayList<String[]>();
        add(form, "grant_type", info.getGrant().getValue());
        switch (info.getGrant()) {
            case JWT_BEARER:
                add(form, "assertion", JwtAssertion.grantAssertion(info, now));
                break;
            case REFRESH_TOKEN:
                add(form, "refresh_token", info.getRefreshToken());
                break;
            case CLIENT_CREDENTIALS:
            default:
                break;
        }
        if (!scopes.isEmpty()) {
            add(form, "scope", String.join(" ", scopes));
        }
        for (Map.Entry<String, String> p : info.getTokenParameters().entrySet()) {
            add(form, p.getKey(), p.getValue());
        }
        Map<String, String> headers = new LinkedHashMap<String, String>();
        headers.put("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8");
        headers.put("Accept", "application/json");
        switch (authentication) {
            case CLIENT_SECRET_BASIC:
                // RFC 6749 section 2.3.1: both parts form-encoded before Base64
                String credentials = formEncode(info.getClientId()) + ":" + formEncode(info.getClientSecret());
                headers.put("Authorization", "Basic "
                        + Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8)));
                break;
            case CLIENT_SECRET_POST:
                add(form, "client_id", info.getClientId());
                add(form, "client_secret", info.getClientSecret());
                break;
            case PRIVATE_KEY_JWT:
                add(form, "client_id", info.getClientId());
                add(form, "client_assertion_type", JwtAssertion.CLIENT_ASSERTION_TYPE);
                add(form, "client_assertion", JwtAssertion.clientAssertion(info, tokenUrl, now));
                break;
            case NONE:
                // the JWT bearer assertion's iss names the client; DocuSign and Salesforce document only
                // grant_type and assertion
                if (info.getGrant() != Grant.JWT_BEARER) {
                    add(form, "client_id", info.getClientId());
                }
                break;
            case MUTUAL_TLS: // the certificate in the TLS handshake is the credential
            default:
                add(form, "client_id", info.getClientId());
                break;
        }
        return HttpRequest.post(tokenUrl, headers, encodeForm(form)).withClientCertificate(info.getClientCertificate());
    }

    /**
     * The token from the answer. Token requests are sent not resendable, so the body of a 401 answer can't be read.
     *
     * @param sent the credentials sent, removed from any server text put in an exception
     */
    private static AccessToken parse(HttpResponse response, Instant sentAt, List<String> sent, Clock clock) {
        Map<String, Object> body = parseBody(response);
        if (!response.isSuccessful()) {
            if (body == null && response.getStatus() == 401) {
                // RFC 6749 section 5.2: a 401 from the token endpoint means invalid_client
                throw new OAuthServiceException("HTTP 401: invalid_client - client authentication failed",
                        "invalid_client", "client authentication failed", null, 401, null);
            }
            throw errorFrom(response, body, sent, clock);
        }
        if (body == null || body.get("access_token") == null) {
            throw new OAuthServiceException("The token response has no access_token", "invalid_response", null, null,
                    response.getStatus(), null);
        }
        if (unsafeHeaderValue(str(body.get("access_token"))) || unsafeHeaderValue(str(body.get("token_type")))) {
            // these go into an Authorization header: no spaces, control characters or non-ASCII
            throw new OAuthServiceException("The token response has characters not allowed in an HTTP header",
                    "invalid_response", null, null, response.getStatus(), null);
        }
        try {
            return AccessToken.fromResponse(body, sentAt);
        } catch (IllegalArgumentException e) {
            throw new OAuthServiceException(e.getMessage(), "invalid_response", null, null, response.getStatus(), e);
        }
    }

    /**
     * The server's error; its text cleaned of the credentials sent, in case the server echoes the request.
     * A 429 or 503 carries the server's Retry-After, so the token cache waits at least that long.
     */
    private static OAuthServiceException errorFrom(HttpResponse response, Map<String, Object> body, List<String> sent,
                                                   Clock clock) {
        String error = body == null ? null : scrub(str(body.get("error")), sent);
        String description = body == null ? null : scrub(str(body.get("error_description")), sent);
        String uri = body == null ? null : scrub(str(body.get("error_uri")), sent);
        StringBuilder msg = new StringBuilder("HTTP ").append(response.getStatus());
        if (error != null) {
            msg.append(": ").append(Strings.safe(error));
            if (description != null) {
                msg.append(" - ").append(Strings.safe(description));
            }
        } else {
            // cleaned before cutting, so a credential cut in half can't slip through
            msg.append(": ").append(Strings.safe(truncate(scrub(response.getBody(), sent))));
        }
        Duration retryAfter = null;
        if (response.getStatus() == 429 || response.getStatus() == 503) {
            long ms = HttpExecutor.retryAfterMillis(response.header("Retry-After"), clock);
            if (ms >= 0) {
                retryAfter = Duration.ofMillis(Math.min(ms, ClientInfo.MAX_TOKEN_RETRY_DELAY_LIMIT.toMillis()));
            }
        }
        return new OAuthServiceException(msg.toString(), error, description, uri, response.getStatus(), retryAfter, null);
    }

    /**
     * JSON, or form-encoded for the few servers that still answer that way; {@code null} if neither.
     *
     * @throws OAuthServiceException if a successful answer is larger than {@link #MAX_RESPONSE_CHARS}
     */
    static Map<String, Object> parseBody(HttpResponse response) {
        String text = response.getBody().trim();
        if (text.isEmpty()) {
            return null;
        }
        if (text.length() > MAX_RESPONSE_CHARS) {
            if (!response.isSuccessful()) {
                return null; // an error page: reported by its status
            }
            throw new OAuthServiceException("The response is larger than " + MAX_RESPONSE_CHARS / 1024 + " KB",
                    "invalid_response", null, null, response.getStatus(), null);
        }
        if (text.startsWith("{")) {
            try {
                return Json.parseObject(text);
            } catch (IllegalArgumentException e) {
                return null;
            }
        }
        String type = response.header("Content-Type");
        if ((type != null && type.toLowerCase(Locale.ROOT).contains("x-www-form-urlencoded"))
                || (text.contains("=") && !text.contains(" "))) {
            return parseForm(text);
        }
        return null;
    }

    /** The credentials in a token request: the Basic header's value and the credential form fields. */
    private static List<String> credentialsIn(HttpRequest request) {
        List<String> out = new ArrayList<String>();
        String authorization = request.getHeaders().get("Authorization");
        if (authorization != null && authorization.startsWith("Basic ")) {
            out.add(authorization.substring(6));
        }
        byte[] body = request.getBody();
        if (body != null) {
            Map<String, Object> form = parseForm(new String(body, StandardCharsets.UTF_8));
            for (String name : CREDENTIAL_FIELDS) {
                if (form.get(name) != null) {
                    out.add(form.get(name).toString());
                }
            }
        }
        return out;
    }

    /** {@code text} with every sent credential, as is or form-encoded, replaced by {@code ****}. */
    static String scrub(String text, List<String> sent) {
        if (text == null) {
            return null;
        }
        String out = text;
        for (String credential : sent) {
            if (credential == null || credential.length() < MIN_SCRUB_LENGTH) {
                continue;
            }
            out = out.replace(credential, "****");
            String encoded = formEncode(credential);
            if (!encoded.equals(credential)) {
                out = out.replace(encoded, "****");
            }
        }
        return out;
    }

    /** Parses {@code a=1&b=2}; the first occurrence of a name wins. */
    private static Map<String, Object> parseForm(String text) {
        Map<String, Object> map = new LinkedHashMap<String, Object>();
        for (String pair : text.split("&")) {
            if (pair.isEmpty()) {
                continue;
            }
            int i = pair.indexOf('=');
            String name = formDecode(i < 0 ? pair : pair.substring(0, i));
            String value = i < 0 ? "" : formDecode(pair.substring(i + 1));
            if (!map.containsKey(name)) {
                map.put(name, value);
            }
        }
        return map;
    }

    private static void add(List<String[]> form, String name, String value) {
        if (value != null) {
            form.add(new String[] {name, value});
        }
    }

    static String encodeForm(List<String[]> form) {
        StringBuilder sb = new StringBuilder();
        for (String[] p : form) {
            if (sb.length() > 0) {
                sb.append('&');
            }
            sb.append(formEncode(p[0])).append('=').append(formEncode(p[1]));
        }
        return sb.toString();
    }

    static String formEncode(String s) {
        try {
            return URLEncoder.encode(s, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String formDecode(String s) {
        try {
            return URLDecoder.decode(s, "UTF-8");
        } catch (UnsupportedEncodingException | IllegalArgumentException e) {
            return s;
        }
    }

    private static String str(Object o) {
        return o == null ? null : o.toString();
    }

    private static boolean unsafeHeaderValue(String v) {
        if (v == null) {
            return false;
        }
        for (int i = 0; i < v.length(); i++) {
            char c = v.charAt(i);
            if (c < 0x21 || c > 0x7e) {
                return true;
            }
        }
        return false;
    }

    /** Where to send a token request, and how the client authenticates there. */
    private static final class Endpoint {

        final String url;
        final ClientInfo.ClientAuthentication authentication;

        Endpoint(String url, ClientInfo.ClientAuthentication authentication) {
            this.url = url;
            this.authentication = authentication;
        }
    }

    private static String truncate(String s) {
        String t = s == null ? "" : s.trim();
        return t.length() <= MAX_ERROR_BODY ? t : t.substring(0, MAX_ERROR_BODY) + "...";
    }
}
