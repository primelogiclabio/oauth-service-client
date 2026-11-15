# oauth-service-client: how the library works

A Java 8+ library for backend services that call OAuth-protected APIs. You describe each service and tenant once in a `ClientInfo`; the library gets the access token, keeps it until shortly before it expires, attaches it and makes the request.

3 grants · 5 client authentication methods · 1 runtime dependency (Caffeine 2.9.3) · built and tested on Java 8 and 21

The same content, with diagrams, is in [library-overview.html](library-overview.html).

## What it does

Your backend calls external services such as DocuSign, Salesforce, Jira, Vertex, Microsoft Entra ID apps, Okta, Auth0 and Oracle Integration, often once per customer (tenant). Each one wants an access token from its token endpoint. This library takes that work off the calling code:

- It sends the token request for the configured **grant** (client credentials, JWT bearer or refresh token), with the right **client authentication**.
- It caches tokens per **service, tenant, user and scope set** and renews them 5 minutes before they expire, one renewal at a time.
- It sends your call to the service with the token attached and hands back every answer, whatever its status.
- It retries only when that is safe, and reports every failure as one exception type with the server's OAuth error.

> **No browser, no `/authorize` call.** All three grants are a single POST to the token endpoint. Where a vendor needs a person's approval first (Jira 3LO apps, DocuSign consent), that happens once, outside the library; the caller then passes the resulting refresh token, or relies on the recorded consent.

The core is generic: it implements the standards (RFC 6749, 7523, 8705) and handles vendor differences through generic settings such as `tokenParameter`, `assertionAudience`, `assertionClaim` and `clientSecretInBody`. Vendor-specific clients are planned as a separate layer on top.

## What works today

| Part | Status | Notes |
|---|---|---|
| `ClientInfo`, `ClientKey`, `Grant` | Done | Public. Builder that reports every problem at once; secrets never printed. |
| Token requests | Done | All three grants and five client authentication methods; tested against a stub server and a live Keycloak. |
| Token cache | Done | Per (service, tenant, user, scope set), on Caffeine 2.9.3. |
| Scopes passed by the app | Done | Replace the `ClientInfo` defaults for that token. |
| `OAuthServiceException` | Done | Public. |
| `OAuthServiceClient`, `ServiceRequest`, `ServiceResponse` | Done | Public. `get`, `post`, `put`, `patch`, `delete`, `request(ServiceRequest)` and `token()`; each call is sent once. |
| Outbound requests | Done | Renew once after a 401, retries (`Retry-After` in seconds or as a date), `retryOnFailure()`, `builder()` settings and a per-call timeout; the mutual TLS socket factory kept per key. |
| PATCH | Done | Java 11 and later, through `java.net.http` under the same rules; a clear error on Java 8. |
| Introspection (RFC 7662) | Planned | For tokens that carry no expiry (Salesforce). `introspectionUrl` can already be set but isn't used yet. |
| Metadata discovery (RFC 8414) | Planned | An issuer instead of an explicit token URL. |
| Refresh-token rotation write-back, cool-down after failures, vendor clients | Planned | See [PROGRESS.md](../PROGRESS.md). |
| DPoP, PS256 signing | Parked | Not planned yet. |

## How the pieces fit

```text
Your service --(ClientInfo)--> OAuthServiceClient ------- Bearer token, TLS -------> Service API
                                 initialize, get/post/                           (any answer comes back)
                                 put/delete, request, token
                                        |
                                        | get(info, scopes)
                                        v
                                   TokenCache           per service, tenant, scope set
                                        | on a miss
                                        v
   JwtAssertion, Jws  <---------   TokenClient          form + client authentication
   (RS256, ES256/384/512)               |
                                        v
   Tls (client certificate) <---   HttpExecutor -> UrlConnectionTransport ---POST, TLS---> token endpoint
                                   (https only, safe retries, deadline)
```

Everything below `OAuthServiceClient` is package-private, so the public surface stays small. Service calls go through the same `HttpExecutor` and transport as token requests.

| Class | Visibility | Job |
|---|---|---|
| `OAuthServiceClient` | public | The entry point: `initialize`, the calls, `token()`, `close`. |
| `ServiceRequest`, `ServiceResponse` | public | One call (method, URL, headers, body, scopes or the caller's token) and its answer. |
| `ClientInfo`, `ClientKey`, `Grant` | public | How to get tokens for one service and tenant; the key or certificate; the grant. |
| `AccessToken` | public | The token, its type, scope, expiry and every other response field (e.g. Salesforce's `instance_url`). |
| `OAuthServiceException` | public | Every failure without a usable answer. |
| `TokenCache` | package | Reuse, renewal, one renewal per key, eviction. |
| `TokenClient` (a `TokenFetcher`) | package | Builds and sends the token request, reads the answer. |
| `JwtAssertion`, `Jws` | package | Signed JWTs for the JWT bearer grant and `private_key_jwt`. |
| `HttpExecutor`, `UrlConnectionTransport`, `Tls` | package | Retries and the overall deadline; HTTP over the JDK's `HttpURLConnection`; the TLS socket factory for a client certificate. |

## Calling a service

```java
try (OAuthServiceClient service = new OAuthServiceClient()) {
    service.initialize(clientInfo);
    ServiceResponse created = service.post(url, json);   // also get, put, delete
    ServiceResponse mine = service.get(myToken, url);    // your own token
    ServiceResponse custom = service.request(ServiceRequest.put(url, xml)
            .contentType("application/xml")
            .header("Accept", "application/json")
            .scopes("items.write"));
    String instanceUrl = (String) service.token().getField("instance_url");
}
```

```java
OAuthServiceClient service = OAuthServiceClient.builder()
        .connectTimeout(Duration.ofSeconds(10))   // defaults shown
        .readTimeout(Duration.ofSeconds(30))
        .callTimeout(Duration.ofSeconds(60))      // attempts, pauses, the resend after a 401
        .retries(2)
        .maxResponseBytes(16 * 1024 * 1024)
        .build();
```

- **Methods:** GET, HEAD, POST, PUT, PATCH, DELETE and OPTIONS; GET, HEAD, DELETE and OPTIONS take no body. PATCH needs Java 11 or later: `HttpURLConnection` can't send it, so it goes through Java's `java.net.http` client under the same TLS, certificate, timeout, size and redirect rules. On Java 8 it fails with a clear error. It can't go through a proxy that asks for a login, and it's refused when a JVM-wide setting would break the rules: `jdk.httpclient.enableAllMethodRetry=true` (Java would resend it) or a SOCKS proxy (`java.net.http` would connect directly).
- **Body:** a String goes as UTF-8 with `Content-Type: application/json; charset=UTF-8` unless you set a content type; bytes go as `application/octet-stream`.
- **Headers:** any valid header except `Authorization` (pass your own token instead) and the ones the JDK sets itself (`Host`, `Content-Length`, `Connection`, ...).
- **The token:** the library's, from the cache, for the request's scopes or else the `ClientInfo` defaults; or your own, sent as `Bearer` as is, never cached or renewed, and with nothing of the `ClientInfo` (no client certificate, so no allowed-host check either). A request can't carry both scopes and your own token.
- **The answer:** every status comes back as a `ServiceResponse`: `getStatus()`, `getHeader(name)`, `getBody()` (text by the Content-Type charset) and `getBodyBytes()` (a PDF arrives intact). Up to 16 MB.
- **Retries:** a call is resent when nothing was sent, or after a 429 or 503 with `Retry-After`; `retryOnFailure()` adds 5xx and other failures for idempotent calls. A POST is sent in a mode that stops Java itself from sending it twice; Java may resend a GET, PUT or DELETE once if the connection fails before the answer. Redirects aren't followed, so the token never goes to another host.
- **401:** with the library's token, the token is renewed once (one token request, shared by every thread holding it) and the call sent once more, if the token is at least 60 s old and the call has time left. A token just issued that's turned away isn't the problem (a permission error, a wrong audience), and renewing it every time would use up a vendor's token limit. With your own token the 401 comes back.
- **Settings:** `OAuthServiceClient.builder()` sets the timeouts, the retries and the response size limit; `ServiceRequest.timeout(...)` sets one call's limit, for a large download. The timeouts also apply to the instance's token requests.
- **Checked first:** the URL must be https before any token is fetched; a bad URL or token gives an `IllegalArgumentException` that doesn't repeat the value.
- **Client certificate:** presented on calls with the library's token whenever the `ClientInfo` has one, for certificate-bound tokens; never with your own token.
- **Allowed hosts:** with `allowedHost(...)` set, a call with the library's token to any other host is refused with an `IllegalArgumentException` before a token is fetched. The list is part of what identifies a cached token, so a `ClientInfo` without it doesn't reuse the token.
- **Lifetime:** `initialize` can be called again, for example after a secret rotation. Tokens are cached for the whole JVM (per class loader), so they outlive `close()` and instances with the same `ClientInfo` share them. One instance is thread-safe; after `close()` calls throw `IllegalStateException`.

## One token, step by step

1. A call on `OAuthServiceClient` (or `token()`) asks the cache for a token with the `ClientInfo` and, optionally, the request's scopes.
2. The cache works out the scope set (the caller's, else the `ClientInfo` defaults) and looks up (service, tenant, user, scope set). A token is reused if the settings that shape it still match and it isn't within 5 minutes of expiry.
3. Otherwise one thread claims the renewal; other threads either keep using the current token if it hasn't expired yet, or wait and share the result.
4. `TokenClient` builds the form for the grant, adds client authentication, signs any assertion with a fresh `jti`, and attaches the client certificate if one is set.
5. `HttpExecutor` checks the URL is https and the headers are clean, then sends. It resends only when the server certainly didn't process the request.
6. The answer is parsed (JSON, or form-encoded), checked, and turned into an `AccessToken` whose expiry comes from the JWT's `exp` or from `expires_in`.
7. The cache stores it and hands it to every waiting thread. If the request failed but the old token hasn't expired, the old token is used and the failure logged.

## ClientInfo settings

Build one with `ClientInfo.forTenant(service, tenant)` or `ClientInfo.global(service)`. `build()` checks everything and throws one `IllegalArgumentException` listing every problem, with no secrets in the message. The result is immutable and thread-safe.

| Builder method | Needed for | What it does |
|---|---|---|
| `forTenant(service, tenant)` / `global(service)` | always | Names the cache entry. Global is a flag, not a "GLOBAL" tenant, so a real tenant coded GLOBAL can't collide. |
| `tokenUrl` | always | The token endpoint; https only, no user info, fragment or backslash; a query is allowed. |
| `grant` | optional | `CLIENT_CREDENTIALS` (default), `JWT_BEARER` or `REFRESH_TOKEN`. |
| `clientId` | always | The registered client ID; also the `iss` of every assertion. |
| `clientSecret`, `clientSecretInBody` | secret clients | Sent in a Basic header by default, in the form when `clientSecretInBody(true)`. |
| `signingKey` | JWT bearer, `private_key_jwt` | A `ClientKey` (RSA of 2048 bits or more, or EC on P-256/384/521), with an optional certificate and key ID. |
| `clientCertificate` | mutual TLS | A `ClientKey` with a certificate; presented in the TLS handshake whenever set. |
| `subject` | JWT bearer; refresh token (required) | The user: for JWT bearer the assertion's `sub` (a DocuSign user ID, a Salesforce username), defaulting to the client ID; for a refresh token the user it belongs to, never sent. Part of the cache key. |
| `assertionAudience` | JWT bearer (required); `private_key_jwt` (optional) | The assertion's `aud`; for a client assertion it defaults to the token URL. |
| `assertionClaim(name, value)` | optional | Extra string claims, e.g. DocuSign's `scope`. `iss`, `sub`, `aud`, `exp`, `iat`, `nbf`, `jti` are refused. |
| `refreshToken` | refresh token grant | The refresh token from an earlier consent. |
| `scope(...)` | optional | Default scopes, one per argument; the app's scopes replace them per request. |
| `tokenParameter(name, value)` | optional | Extra form fields, e.g. `audience`. Names the library sets (`grant_type`, `scope`, `client_id`, …) are refused. |
| `introspectionUrl` | planned | Stored and checked now; used once introspection is built. |
| `attribute(name, value)` | optional | The caller's own data (an account ID, a base URL); never sent. |
| `allowedHost(...)` | optional, recommended | Hosts that calls with this token may go to: `api.example.com`, or `*.my.salesforce.com` for any host below that domain (not over an IP address). Without any, every https host is allowed. Keep wildcards narrow: `*.co.uk` or `*.azurewebsites.net` would let anyone with a site there receive the token. |

Settings that don't fit the grant are refused rather than ignored: a `subject` with client credentials, a refresh token without one, a `refreshToken` outside the refresh grant, a secret and a signing key both used to authenticate the client, an expired certificate.

## Choosing client authentication

There is no setting for the method: it follows from what is set, in this order.

```text
signing key set, and grant isn't JWT bearer? --yes--> private_key_jwt
        | no
client secret set? ---------------------------yes--> Basic header, or form with clientSecretInBody(true)
        | no
client certificate set? ----------------------yes--> mutual TLS + client_id
        | no
        +------------------------------------------> none: client_id, or nothing with JWT bearer
```

With the JWT bearer grant the signing key signs the grant's assertion, so a secret, if set, authenticates the client (Oracle Identity, Keycloak). A client certificate is presented in the TLS handshake whenever it is set, even when a secret or key authenticates, so certificate-bound tokens work.

## What goes on the wire

Every token request is a POST with `Content-Type: application/x-www-form-urlencoded; charset=UTF-8` and `Accept: application/json`. The form fields come in this order: the grant fields, then `scope` (the scopes joined by spaces, only when there are any), the token parameters in the order set, then the client authentication fields.

| Grant | Grant fields |
|---|---|
| Client credentials | `grant_type=client_credentials` |
| JWT bearer | `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`, `assertion` |
| Refresh token | `grant_type=refresh_token`, `refresh_token` |

| Client authentication | Added |
|---|---|
| Basic | Header `Authorization: Basic base64(urlencode(client_id) ":" urlencode(secret))`, as RFC 6749 §2.3.1 says |
| Secret in the form | `client_id`, `client_secret` |
| `private_key_jwt` | `client_id`, `client_assertion_type`, `client_assertion` |
| Mutual TLS | `client_id`; the certificate goes in the handshake |
| None | `client_id`, except with JWT bearer, which sends only `grant_type` and `assertion` (as DocuSign and Salesforce document) |

```http
POST /oauth/token HTTP/1.1
Host: auth.vertexcloud.com
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Accept: application/json
Authorization: Basic Y2xpZW50OnNlY3JldA==

grant_type=client_credentials&scope=payroll-calculation&audience=verx%3A%2F%2Fmigration-api
```

## Signed assertions

Both the JWT bearer grant and `private_key_jwt` use a JWT signed with the `signingKey`. A new one is built for every attempt, so a retry never reuses a `jti`.

| Part | Value |
|---|---|
| `alg` | RS256 for RSA keys; ES256, ES384 or ES512 by the EC key's curve. There is no setting yet. |
| `typ` | `JWT` |
| `kid` | The key ID, when the `ClientKey` has one (`withKeyId`). |
| `x5t#S256`, `x5t` | SHA-256 and SHA-1 thumbprints of the certificate, when the key has one (Entra ID, Oracle Identity). |
| `iss` | The client ID. |
| `sub` | Grant assertion: `subject`, else the client ID. Client assertion: the client ID. |
| `aud` | Grant assertion: `assertionAudience`. Client assertion: `assertionAudience`, else the token URL. |
| `jti` | A random UUID, new every time. |
| `iat`, `nbf`, `exp` | Now, now, and now + 60 seconds (Salesforce allows 3 minutes at most, Auth0 5). |
| Extra claims | Each `assertionClaim`, after the standard ones. |

## Token cache

```text
token request sent                                expiry - 5 min      expiry
|------------- get() returns the cached token -------|---- renewed ----|  evicted
renew(info, scopes, rejected) after a 401: drops that token and fetches once,
shared by every caller holding it.
```

For a token that lives less than 10 minutes, the margin is half its lifetime instead of 5 minutes.

- **Key:** service, tenant (or global), user and the scope set. The user is the `subject` of a JWT bearer or refresh token grant; client credentials have none, since their token serves the whole tenant. The same scopes in another order share a token; different scopes get their own.
- **Settings must match:** a cached token is reused only while the settings that shape it are unchanged (token URL, grant, client ID, subject, audience, assertion claims, default scopes, token parameters, client certificate). A rotated secret, key or refresh token keeps it.
- **One renewal per key:** through a map of in-flight renewals, not inside Caffeine's `compute`, so a slow token endpoint for one key never blocks others. Waiting threads share the new token or the failure.
- **Failures:** if a renewal fails while the current token hasn't expired, the current token is returned and a warning logged.
- **Unknown expiry:** a token that says nothing about its expiry is kept until `renew` is called after a 401.
- **Bounds:** at most 10,000 entries; expired entries are evicted (in buckets of about a second, so `size()` can lag while reads check expiry exactly).

## Scopes from the app

Often only the calling code knows which scopes a call needs, so it can pass them with each request. The rule is simple: **the app's scopes, when given, are used for that token; otherwise the `ClientInfo` defaults**. The app's scopes are checked like the defaults: trimmed, not blank, no spaces inside one, duplicates dropped, order kept.

```java
ClientInfo graph = ClientInfo.global("graph")
        .tokenUrl("https://login.microsoftonline.com/" + directoryId + "/oauth2/v2.0/token")
        .clientId(applicationId)
        .signingKey(ClientKey.fromKeyStore(pkcs12, password))
        .build();                                    // no default scopes

service.initialize(graph);
service.request(ServiceRequest.get(usersUrl).scopes("https://graph.microsoft.com/.default"));
AccessToken token = service.token("https://graph.microsoft.com/.default");   // the same cached token
```

## How expiry is decided

1. **The JWT's `exp`**, when the access token is a JWT: that's what the service checks. If the token's `iat` is later than the moment the request was sent, the server's clock runs ahead and `exp` is moved back by the gap.
2. **`expires_in`** from the response, counted from when the request was sent, limited to 0 to 10 years.
3. **Introspection** (planned): ask `introspectionUrl` for the token's `exp`.
4. **Unknown**: no guessed lifetime; the token is used until the service answers 401.

## Retries and timeouts

Token requests are resent only when the server certainly didn't process them, because some vendors cap token requests (Vertex: 10 per 8 hours) and a resent rotating refresh token can revoke the whole chain.

| What happened | Token request |
|---|---|
| Connection refused, host not found, connect timeout | Resent, after 500 ms, then 1 s |
| 429, or 503 with `Retry-After` in seconds | Resent after that delay (at most 30 s) |
| 500, 502, 504, a 503 without `Retry-After`, a read timeout | Not resent: reported |
| TLS handshake failed | Not resent: it would fail the same way |
| An OAuth error (400, 401) | Not resent: reported with its `error` (a 401 as `invalid_client`) |

A service call follows the same idea: by default it is resent only when the service certainly didn't carry it out. `ServiceRequest.retryOnFailure()` adds 5xx, a busy answer without `Retry-After` and connection failures after sending, for idempotent calls (a POST may then be carried out twice); never a read timeout, since the service may still be working on the call. When `Retry-After` asks for more than 30 s, can't be read, or the pause doesn't fit in what is left of the call's timeout, the answer comes back instead.

| What happened | Service call | With `retryOnFailure()` |
|---|---|---|
| Connection refused, host not found, connect timeout | Resent, after 500 ms, then 1 s | Resent |
| 429 or 503 with `Retry-After` (seconds or a date) of at most 30 s | Resent after that pause | Resent after that pause |
| 429 or 503 without `Retry-After` | Returned | Resent, after 500 ms, then 1 s |
| 500, 502, 504 | Returned | Resent |
| Connection lost after sending | Reported | Resent |
| 401 with the library's token | Token renewed once, call sent once more | The same |
| 401 with your own token | Returned | Returned |

| Limit | Value |
|---|---|
| Connect timeout / read timeout | 10 s / 30 s (`connectTimeout`, `readTimeout`) |
| Whole call: attempts, pauses, the resend after a 401 | 60 s (`callTimeout`, or `ServiceRequest.timeout`); a token request has its own limit of the same length |
| Retries | Token requests 2; service calls 2 by default (`retries`, 0 to 10) |
| Token response size | 1 MB read, 256 KB used |
| Service response size | 16 MB (`maxResponseBytes`) |
| Requests in flight per host / worker threads | 32 / 64, per JVM |

Every token request, and every POST to a service, is also sent in a mode that stops Java from silently resending it. Redirects are never followed. The settings come from `OAuthServiceClient.builder()`, and the timeouts also apply to the instance's token requests. A client certificate's TLS context is made once per `ClientKey` and reused, so its TLS sessions are too.

## Errors

| Exception | When | Carries |
|---|---|---|
| `IllegalArgumentException` | `ClientInfo.build()` finds problems; a blank scope or one with spaces; a `ServiceRequest` with a non-https URL, a refused header, a body on GET, PATCH on Java 8, or a bad token | Every problem in one message, naming service and tenant; never a URL's path or query, a header value or a token (host names may appear) |
| `IllegalStateException` | A call needs the library's token but `initialize` wasn't called; any call after `close()` | |
| `OAuthServiceException` | No usable token: the server answered with an error, the answer isn't a token, the connection, TLS or deadline failed, the thread was interrupted. Or a service call got no answer: connection, TLS, timeout, a response over 16 MB | `getError()`, `getErrorDescription()`, `getErrorUri()`, `getHttpStatus()` (-1 without an answer); the message starts "Token request for service/tenant failed" or "Request failed: METHOD url" (query hidden) |

Messages never contain secrets, tokens or assertions. Server text is cleaned of control characters (so it can't forge log lines) and a non-OAuth error body is cut to 500 characters; credentials the server echoes back are replaced by `****`. A response whose `access_token` or `token_type` isn't safe in an HTTP header is rejected.

## ClientInfo per service

These match the tests in `ClientInfoTest`; [services.md](services.md) has each vendor's details and sources.

```java
// DocuSign: JWT bearer per tenant; scopes go in the assertion
ClientInfo.forTenant("docusign", tenant)
        .tokenUrl("https://account-d.docusign.com/oauth/token")
        .grant(Grant.JWT_BEARER)
        .clientId(integrationKey)
        .signingKey(ClientKey.fromPem(rsaPrivateKeyPem))      // PKCS#1 PEM is fine
        .subject(userId)
        .assertionAudience("account-d.docusign.com")
        .assertionClaim("scope", "signature impersonation")
        .attribute("accountId", accountId)
        .build();

// Salesforce: JWT bearer, one integration for all tenants
ClientInfo.global("salesforce")
        .tokenUrl("https://login.salesforce.com/services/oauth2/token")
        .grant(Grant.JWT_BEARER)
        .clientId(consumerKey)
        .signingKey(ClientKey.fromPem(keyPem))
        .subject("integration@example.com")
        .assertionAudience("https://login.salesforce.com")
        .build();

// Microsoft Entra ID: certificate credential (private_key_jwt with x5t#S256)
ClientInfo.global("graph")
        .tokenUrl("https://login.microsoftonline.com/" + directoryId + "/oauth2/v2.0/token")
        .clientId(applicationId)
        .signingKey(ClientKey.fromKeyStore(pkcs12, password))
        .scope("https://graph.microsoft.com/.default")
        .build();

// Okta: private_key_jwt with a key ID
ClientInfo.forTenant("okta", tenant)
        .tokenUrl("https://acme.okta.com/oauth2/default/v1/token")
        .clientId(clientId)
        .signingKey(ClientKey.fromPem(keyPem).withKeyId("kid-1"))
        .scope("custom.read")
        .build();

// Auth0 and Vertex: client credentials with an audience parameter
ClientInfo.forTenant("vertex", tenant)
        .tokenUrl("https://auth.vertexcloud.com/oauth/token")
        .clientId(clientId).clientSecret(secret)
        .tokenParameter("audience", "verx://migration-api")
        .scope("payroll-calculation")
        .build();

// Jira service account: secret in the form body
ClientInfo.forTenant("jira", tenant)
        .tokenUrl("https://auth.atlassian.com/oauth/token")
        .clientId(clientId).clientSecret(secret).clientSecretInBody(true)
        .attribute("cloudId", cloudId)
        .build();

// Oracle Integration: JWT user assertion, client authenticated with its secret
ClientInfo.forTenant("oic", tenant)
        .tokenUrl("https://idcs-abc.identity.oraclecloud.com/oauth2/v1/token")
        .grant(Grant.JWT_BEARER)
        .clientId(clientId).clientSecret(secret)
        .signingKey(ClientKey.fromPem(keyPem, certPem))      // x5t from the certificate
        .subject("integration.user")
        .assertionAudience("https://idcs-abc.identity.oraclecloud.com")
        .scope(oicScope)
        .build();

// Mutual TLS: the certificate is the credential
ClientInfo.global("bank")
        .tokenUrl("https://auth.example.com/token")
        .clientId(clientId)
        .clientCertificate(ClientKey.fromPem(keyPem, chainPem))
        .build();
```

## Security notes

- **Who shares a token:** tokens are cached per service, tenant, user and scopes. A client credentials token serves the whole tenant (server to server). With the JWT bearer grant the user is the `subject`; with a refresh token the `subject` names the user the refresh token belongs to and is required, so one user never gets another user's token.
- **Trusted configuration:** build `ClientInfo` from your own configuration, not from tenant input: a tenant that could set the token URL and audience could collect an assertion signed with your key. Anything in the same class loader that builds a `ClientInfo` with the same service, tenant, user, token URL and client ID gets the cached token, so don't share the jar between applications that don't trust each other (a server's shared `lib/` folder).
- **TLS:** the library uses its own TLS context with the JVM's trust store (`cacerts`, or `javax.net.ssl.trustStore`), checks host names itself and presents no client certificate unless the `ClientInfo` has one. Settings other code makes JVM-wide (a socket factory or host name verifier that accepts anything, `javax.net.ssl.keyStore`, `jdk.internal.httpclient.disableHostnameVerification` for PATCH) don't apply.
- **Deadlines:** at the call deadline the request's sockets are closed, so a server that stalls the connection or the TLS handshake can't hold a thread or a host slot.
- **At most once:** every token request and every POST to a service is sent in a mode that stops Java from resending it; a 401 answer's body can't be read in that mode, so a token endpoint's 401 is reported as `invalid_client`. A PATCH isn't resent by Java either (and is refused if a JVM-wide setting would change that). Java may resend a GET, PUT or DELETE once when a connection fails before the answer.
- **Java's Authenticator:** on Java 9 and later the JVM's default `java.net.Authenticator` is asked only for proxy logins, never for a service's 401 login challenge. On Java 8 that holds for POSTs only: an application on Java 8 with a default Authenticator should make it check `getRequestorType()`.
- **Messages and logs:** never a secret, token or assertion; credentials a server echoes back in an error are replaced by `****`; URLs are shown without user info or query.
- **Allowed hosts:** set `allowedHost(...)` on each `ClientInfo` whenever a URL can come from a response (Salesforce's `instance_url`, a Graph next link, DocuSign's `base_uri`): a call to any other host is then refused before the token is fetched. Without it, every https host is allowed. Keep wildcards narrow: a public suffix or a shared hosting domain lets everyone there receive the token.
- **Cookies:** don't install a JVM-wide `CookieHandler` (`CookieHandler.setDefault`) in an application that uses this library for several tenants: `HttpURLConnection` would share cookies across all calls, so cookies from one tenant's calls could go out with another's. The library can't turn that off, and logs a warning once when it finds one.

## Testing

- `mvn verify` runs the unit tests on any JDK from 8 up; CI runs them on JDK 8 and 21, on Linux and Windows.
- `TokenClientTest` sends real HTTPS requests to an in-process stub server that uses the test CA in `src/test/resources/tls`, including a server that requires a client certificate.
- `OAuthServiceClientTest` makes service calls to the stub server: each method, headers, the token shared by instances, your own token, every status, binary bodies, the size limit, a client certificate; `ServiceRequestTest` checks every rule of a request.
- `TransportSecurityTest` checks the transport's defences: a stalled TLS handshake ends at the deadline, a trust-all default installed JVM-wide isn't used, TLS sockets check host names, and a service's login challenge never reaches the JVM's Authenticator.
- `KeycloakTokenTest` sends real token requests to a throwaway Keycloak 26.8.1: secret in a header and in the body, `private_key_jwt` with RSA and EC keys, mutual TLS with a certificate-bound token, the JWT bearer grant and the refresh token grant. It also calls Keycloak's userinfo endpoint as a service: a revoked token is renewed after the 401, and a certificate-bound token (RFC 8705) is accepted with its client certificate and refused without it. The README section "Live check against Keycloak" has the commands.
- Key tests are checked by mutation: each check breaks one rule in the code (for example, swap Basic and body, drop `x5t`, leave scopes out of the cache key) and confirms a test fails.

## Planned and out of scope

- **Next:** a security review of the new code and signing, then release 1.0.0 on Maven Central.
- **After the basics:** refresh-token rotation handed back to the caller (Jira 3LO, with a JSON request body), a short cool-down after failed token requests, introspection, metadata discovery, and vendor clients on top of the core.
- **Unverified:** whether Salesforce's token endpoint accepts a Basic header alongside the JWT bearer grant, which introspection there would need.
- **Out of scope:** sign-in and the authorization code flow, DPoP, API keys, OAuth 1.0, request signing (OCI, AWS), the password grant.

## References

### In this repository

- [services.md](services.md): grants and client authentication for each example service, with vendor sources
- [README.md](../README.md): build and the Keycloak live check
- [PROGRESS.md](../PROGRESS.md): decisions, next items and known gotchas

### Standards

- [RFC 6749: OAuth 2.0](https://www.rfc-editor.org/rfc/rfc6749) (§2.3.1 client passwords, §4.4 client credentials, §5 token responses, §6 refresh)
- [RFC 7523: JWT bearer grant and client authentication](https://www.rfc-editor.org/rfc/rfc7523)
- [RFC 7519: JWT](https://www.rfc-editor.org/rfc/rfc7519), [RFC 7515: JWS](https://www.rfc-editor.org/rfc/rfc7515) (`x5t`, `x5t#S256`)
- [RFC 8705: Mutual TLS and certificate-bound tokens](https://www.rfc-editor.org/rfc/rfc8705)
- [RFC 7662: Token introspection](https://www.rfc-editor.org/rfc/rfc7662), [RFC 8414: Server metadata](https://www.rfc-editor.org/rfc/rfc8414) (planned)

### Libraries and tools

- [Caffeine](https://github.com/ben-manes/caffeine) 2.9.3 (the last line that runs on Java 8)
- [Keycloak: JWT Authorization Grant](https://www.keycloak.org/securing-apps/jwt-authorization-grant), used by the live check

*Describes the code as of November 2026: token requests, the public API and outbound requests done.*
