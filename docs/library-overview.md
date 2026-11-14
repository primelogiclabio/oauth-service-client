# oauth-service-client: how the library works

A Java 8+ library for backend services that call OAuth-protected APIs. You describe each service and tenant once in a `ClientInfo`; the library gets the access token, keeps it until shortly before it expires, and (once the public API lands) makes the request.

3 grants · 5 client authentication methods · 1 runtime dependency (Caffeine 2.9.3) · built and tested on Java 8 and 21

The same content, with diagrams, is in [library-overview.html](library-overview.html).

## What it does

Your backend calls external services such as DocuSign, Salesforce, Jira, Vertex, Microsoft Entra ID apps, Okta, Auth0 and Oracle Integration, often once per customer (tenant). Each one wants an access token from its token endpoint. This library takes that work off the calling code:

- It sends the token request for the configured **grant** (client credentials, JWT bearer or refresh token), with the right **client authentication**.
- It caches tokens per **service, tenant and scope set** and renews them 5 minutes before they expire, one renewal at a time.
- It retries only when that is safe, and reports every failure as one exception type with the server's OAuth error.

> **No browser, no `/authorize` call.** All three grants are a single POST to the token endpoint. Where a vendor needs a person's approval first (Jira 3LO apps, DocuSign consent), that happens once, outside the library; the caller then passes the resulting refresh token, or relies on the recorded consent.

The core is generic: it implements the standards (RFC 6749, 7523, 8705) and handles vendor differences through generic settings such as `tokenParameter`, `assertionAudience`, `assertionClaim` and `clientSecretInBody`. Vendor-specific clients are planned as a separate layer on top.

## What works today

| Part | Status | Notes |
|---|---|---|
| `ClientInfo`, `ClientKey`, `Grant` | Done | Public. Builder that reports every problem at once; secrets never printed. |
| Token requests | Done | All three grants and five client authentication methods; tested against a stub server and a live Keycloak. |
| Token cache | Done | Per (service, tenant, scope set), on Caffeine 2.9.3. |
| Scopes passed by the app | Done | Replace the `ClientInfo` defaults for that token. |
| `OAuthServiceException` | Done | Public. |
| Public API: `initialize`, `request`, `close` | Next | Until then the token code is package-private: an application can build a `ClientInfo` but can't get a token yet. |
| Outbound requests | Planned | Attach the token, renew once on 401, timeouts and `Retry-After`. |
| Introspection (RFC 7662) | Planned | For tokens that carry no expiry (Salesforce). `introspectionUrl` can already be set but isn't used yet. |
| Metadata discovery (RFC 8414) | Planned | An issuer instead of an explicit token URL. |
| Refresh-token rotation write-back, cool-down after failures, vendor clients | Planned | See [PROGRESS.md](../PROGRESS.md). |
| DPoP, PS256 signing | Parked | Not planned yet. |

## How the pieces fit

```text
Your service --(ClientInfo)--> [OAuthServiceClient]  - - - - Bearer token - - - -> [Service API]
                                 (next: initialize,                                  (planned)
                                  request, close)
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

Parts in [brackets] are the next items. Everything below `OAuthServiceClient` is package-private, so the public surface stays small.

| Class | Visibility | Job |
|---|---|---|
| `ClientInfo`, `ClientKey`, `Grant` | public | How to get tokens for one service and tenant; the key or certificate; the grant. |
| `AccessToken` | public | The token, its type, scope, expiry and every other response field (e.g. Salesforce's `instance_url`). |
| `OAuthServiceException` | public | Every failure without a usable answer. |
| `TokenCache` | package | Reuse, renewal, one renewal per key, eviction. |
| `TokenClient` (a `TokenFetcher`) | package | Builds and sends the token request, reads the answer. |
| `JwtAssertion`, `Jws` | package | Signed JWTs for the JWT bearer grant and `private_key_jwt`. |
| `HttpExecutor`, `UrlConnectionTransport`, `Tls` | package | Retries and the overall deadline; HTTP over the JDK's `HttpURLConnection`; the TLS socket factory for a client certificate. |

## One token, step by step

1. The caller asks the cache for a token with a `ClientInfo` and, optionally, its own scopes.
2. The cache works out the scope set (the caller's, else the `ClientInfo` defaults) and looks up (service, tenant, scope set). A token is reused if the settings that shape it still match and it isn't within 5 minutes of expiry.
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
| `subject` | JWT bearer | The assertion's `sub` (a DocuSign user ID, a Salesforce username); defaults to the client ID. |
| `assertionAudience` | JWT bearer (required); `private_key_jwt` (optional) | The assertion's `aud`; for a client assertion it defaults to the token URL. |
| `assertionClaim(name, value)` | optional | Extra string claims, e.g. DocuSign's `scope`. `iss`, `sub`, `aud`, `exp`, `iat`, `nbf`, `jti` are refused. |
| `refreshToken` | refresh token grant | The refresh token from an earlier consent. |
| `scope(...)` | optional | Default scopes, one per argument; the app's scopes replace them per request. |
| `tokenParameter(name, value)` | optional | Extra form fields, e.g. `audience`. Names the library sets (`grant_type`, `scope`, `client_id`, …) are refused. |
| `introspectionUrl` | planned | Stored and checked now; used once introspection is built. |
| `attribute(name, value)` | optional | The caller's own data (an account ID, a base URL); never sent. |

Settings that don't fit the grant are refused rather than ignored: a `subject` outside JWT bearer, a `refreshToken` outside the refresh grant, a secret and a signing key both used to authenticate the client, an expired certificate.

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

- **Key:** service, tenant (or global) and the scope set. The same scopes in another order share a token; different scopes get their own.
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

cache.get(graph, Arrays.asList("https://graph.microsoft.com/.default"), tokenClient);   // inside the library today
```

The public `request(...)` will take the same optional scopes argument.

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
| An OAuth error (400, 401) | Not resent: reported with its `error` |

| Limit | Value |
|---|---|
| Connect timeout / read timeout | 10 s / 30 s |
| Whole call, all attempts and pauses | 60 s |
| Retries | 2 (3 attempts) |
| Token response size | 256 KB |
| Requests in flight per host / worker threads | 32 / 64, per JVM |

A refresh token request is also sent in a mode that stops the JDK from silently resending a POST. Redirects are never followed. These limits are fixed for now; the public API item makes them settings.

## Errors

| Exception | When | Carries |
|---|---|---|
| `IllegalArgumentException` | `ClientInfo.build()` finds problems; the app passes a blank scope or one with spaces | Every problem in one message, naming service and tenant |
| `OAuthServiceException` | No usable token: the server answered with an error, the answer isn't a token, the connection, TLS or deadline failed, the thread was interrupted | `getError()`, `getErrorDescription()`, `getErrorUri()`, `getHttpStatus()` (-1 without an answer); the message starts "Token request for service/tenant failed" |

Messages never contain secrets, tokens or assertions. Server text is cleaned of control characters (so it can't forge log lines) and a non-OAuth error body is cut to 500 characters. A response whose `access_token` or `token_type` isn't safe in an HTTP header is rejected.

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

## Testing

- `mvn verify` runs the unit tests on any JDK from 8 up; CI runs them on JDK 8 and 21, on Linux and Windows.
- `TokenClientTest` sends real HTTPS requests to an in-process stub server that uses the test CA in `src/test/resources/tls`, including a server that requires a client certificate.
- `KeycloakTokenTest` sends real token requests to a throwaway Keycloak 26.8.1: secret in a header and in the body, `private_key_jwt` with RSA and EC keys, mutual TLS with a certificate-bound token, the JWT bearer grant and the refresh token grant. The README section "Live check against Keycloak" has the commands.
- Key tests are checked by mutation: each check breaks one rule in the code (for example, swap Basic and body, drop `x5t`, leave scopes out of the cache key) and confirms a test fails.

## Planned and out of scope

- **Next:** the public API (`initialize`, `request`, `close`, with optional scopes per request), then outbound requests, tests for them, and the README examples.
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

*Describes the code as of November 2026: token requests done, public API next.*
