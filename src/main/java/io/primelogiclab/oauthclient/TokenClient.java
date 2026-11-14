package io.primelogiclab.oauthclient;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
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
    /** Most characters of a non-OAuth error body put in an exception message. */
    private static final int MAX_ERROR_BODY = 500;

    private final HttpExecutor http;
    private final Clock clock;

    TokenClient(HttpExecutor http, Clock clock) {
        this.http = http;
        this.clock = clock;
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
        final String tokenUrl = tokenUrl(info);
        final boolean refresh = info.getGrant() == Grant.REFRESH_TOKEN;
        final Instant[] sentAt = new Instant[1];
        try {
            HttpResponse response = http.execute(new Supplier<HttpRequest>() {
                @Override
                public HttpRequest get() {
                    // built anew for every attempt: an assertion's jti may be used only once
                    Instant now = clock.instant();
                    HttpRequest request = tokenRequest(info, scopes, tokenUrl, now);
                    sentAt[0] = now;
                    return refresh ? request.notResendable() : request;
                }
            }, HttpExecutor.Retry.IF_NOT_PROCESSED);
            return parse(response, sentAt[0], refresh);
        } catch (OAuthServiceException e) {
            throw new OAuthServiceException("Token request for " + info.label() + " failed: " + e.getMessage(),
                    e.getError(), e.getErrorDescription(), e.getErrorUri(), e.getHttpStatus(), e);
        }
    }

    /** The token endpoint; the one place to resolve it, e.g. from server metadata later. */
    private static String tokenUrl(ClientInfo info) {
        return info.getTokenUrl();
    }

    /** The token request: grant fields, scope, token parameters, then the client authentication. */
    static HttpRequest tokenRequest(ClientInfo info, List<String> scopes, String tokenUrl, Instant now) {
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
        switch (info.clientAuthentication()) {
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

    /** @param streamed sent not resendable, so the body of a 401 answer can't be read */
    private static AccessToken parse(HttpResponse response, Instant sentAt, boolean streamed) {
        Map<String, Object> body = parseBody(response);
        if (!response.isSuccessful()) {
            if (streamed && body == null && response.getStatus() == 401) {
                // RFC 6749 section 5.2: a 401 from the token endpoint means invalid_client
                throw new OAuthServiceException("HTTP 401: invalid_client - client authentication failed",
                        "invalid_client", "client authentication failed", null, 401, null);
            }
            throw errorFrom(response, body);
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

    private static OAuthServiceException errorFrom(HttpResponse response, Map<String, Object> body) {
        String error = body == null ? null : str(body.get("error"));
        String description = body == null ? null : str(body.get("error_description"));
        String uri = body == null ? null : str(body.get("error_uri"));
        StringBuilder msg = new StringBuilder("HTTP ").append(response.getStatus());
        if (error != null) {
            msg.append(": ").append(Strings.safe(error));
            if (description != null) {
                msg.append(" - ").append(Strings.safe(description));
            }
        } else {
            msg.append(": ").append(Strings.safe(truncate(response.getBody())));
        }
        return new OAuthServiceException(msg.toString(), error, description, uri, response.getStatus(), null);
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

    private static String truncate(String s) {
        String t = s == null ? "" : s.trim();
        return t.length() <= MAX_ERROR_BODY ? t : t.substring(0, MAX_ERROR_BODY) + "...";
    }
}
