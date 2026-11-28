# Changelog

All notable changes to this library. Versions follow [Semantic Versioning](https://semver.org/): from 1.0.0 on, a change that breaks callers only comes with a new major version.

## 1.1.0 (2026-11-27)

The first release on `https://repo.primelogiclab.io/releases`, in the same two flavors: `1.1.0` for Java 21 and later, and `1.1.0-jdk8` for Java 8 to 20. Add that repository to your build (see the README's Install section).

### Added

- **Waiting after a failed token request:** no other token request is sent for the same service, tenant, user and scopes for 5 seconds, doubled with each further failure in a row, up to 5 minutes. A token server's `Retry-After` (429, 503) makes the wait at least that long. Meanwhile calls get the cached token while it hasn't expired, else fail at once with the last failure's `OAuthServiceException` details, so a broken configuration doesn't use up a vendor's cap on token requests. A changed secret, key or setting is tried at once.
- **`ClientInfo.Builder.maxTokenRetryDelay(Duration)`** sets that ceiling, from 0 (no waiting) to 24 hours. For Vertex (10 token requests per 8 hours), 1 hour.
- **The token endpoint from the server's metadata:** `ClientInfo.Builder.issuer(...)` or `metadataUrl(...)` instead of `tokenUrl(...)`. The metadata is read from OpenID Connect discovery or RFC 8414 and kept for a day; if a refresh fails, the copy held stays in use. The document must name the configured issuer exactly. With a client certificate, the mutual TLS alias of the token endpoint is used when listed. When the server lists its client authentication methods without the one the secret would use, the other (Basic header or form body) is used if listed.
- **`ClientInfo.Builder.signingAlgorithm(String)`:** `PS256` makes an RSA key sign its assertions with RSASSA-PSS (SHA-256), which Entra ID recommends for certificate credentials; RS256 stays the default, and an EC key keeps its curve's ES algorithm. `build()` reports a name that doesn't fit the key. Switching it is tried at once after a failed token request, and the cached token stays.
- **`OAuthServiceClient.setMaxRequestsPerHost(int)`** and `getMaxRequestsPerHost()`: the limit on calls in flight to one host at once, still shared JVM-wide by every client and tenant, can now be changed from its default of 32, at once while running. Several instances of an application together send up to that many times the limit.

### Changed

- **Calls waiting for a host are served in the order they came:** when a host's limit is reached, a slot that comes free goes to the call that has waited longest, and a new call waits behind it. Before, every waiting call was woken and any of them, or a new one, could take it.
- **Connections are reused:** calls to a host keep their TCP and TLS connection alive for the next call, per client certificate, instead of opening a new one each time. A token request still gets a connection of its own. A POST that meets a connection the server closes at that moment fails as a connection lost after sending; `retryOnFailure()` resends it. `-Dhttp.keepAlive=false` turns reuse off JVM-wide.
- **Where releases are published:** from 1.1.0 on, both flavors go to `https://repo.primelogiclab.io/releases` (public, no login) instead of Maven Central. Add that repository to your build (see the README's Install section). 1.0.0 stays on Maven Central.

### Known limitations

- **PATCH:**
  - In `1.1.0-jdk8`, it needs Java 11 or later; on Java 8 it fails with a clear error.
  - It can't go through a proxy that asks for a login, and it is refused when a SOCKS proxy or `jdk.httpclient.enableAllMethodRetry=true` is set.
- **Tokens with no expiry:** when a token says nothing about its expiry (no JWT `exp`, no `expires_in`, as with Salesforce), it is kept until the service answers 401. Token introspection (RFC 7662) is planned.
- **Refresh tokens:** a token server that rotates them (Jira 3LO) isn't supported yet. The new refresh token isn't handed back to the caller.
- **No DPoP.** Okta turns "Require DPoP" on by default for new service apps, so turn it off there.
- **Per-host limit per JVM:** the limit on calls in flight to one host counts one JVM only, so several instances of an application together send up to that many times the limit.
- **Cookies:** a JVM-wide `CookieHandler` set by other code also sees the library's calls, because `HttpURLConnection` can't opt out. The library warns once when one is set.

## 1.0.0 (2026-11-15)

The first release, in two flavors with the same API: `1.0.0` for Java 21 and later (on Caffeine 3), and `1.0.0-jdk8` for Java 8 to 20 (on Caffeine 2.9).

### Added

- **Calls with the library's token.** `OAuthServiceClient` gets the token for a `ClientInfo`, attaches it and sends the call: `get`, `post`, `put`, `patch` and `delete` shortcuts, and `request(ServiceRequest)` for other methods, headers, scopes and timeouts. Every HTTP answer comes back as a `ServiceResponse`, whatever its status. Only failures without an answer throw `OAuthServiceException`.
- **Calls with the caller's own token**, used as is: not cached, never renewed, and nothing of the `ClientInfo` attached.
- **Grants:**
  - client credentials
  - JWT bearer (RFC 7523)
  - refresh token
- **Client authentication:**
  - a secret in an HTTP Basic header or in the body
  - `private_key_jwt` with RS256, ES256, ES384 or ES512
  - mutual TLS (RFC 8705)
  - none
- **Keys:** `ClientKey` reads them from PEM (PKCS#8, PKCS#1, SEC1) or a keystore.
- **Token cache:** JVM-wide, per service, tenant, user and scopes, on Caffeine. A token is renewed 5 minutes before it expires, with one renewal per key at a time, and outlives `close()`.
- **Renewal after a 401:** when a service answers 401 to a token at least 60 seconds old, the token is renewed and the call sent once more, within the same deadline.
- **Retries:**
  - By default a call is resent only when nothing was sent, or after a 429 or 503 with `Retry-After` of at most 30 seconds.
  - `ServiceRequest.retryOnFailure()` adds 5xx answers and failures after sending, for idempotent calls.
  - Token requests are resent only when the server certainly didn't process them.
- **Settings:** `OAuthServiceClient.builder()` sets the connect, read and call timeouts, the retries and the response size limit. The defaults are 10 s, 30 s, 60 s, 2 retries and 16 MB.
- **Allowed hosts per `ClientInfo`:** exact hosts or `*.domain`, checked before a token is fetched.
- **Transport security:**
  - https only
  - the library's own TLS context with host name checks
  - redirects not followed
  - the JVM's `Authenticator` used only for proxy logins
  - credentials echoed by a server masked in messages
- **PATCH on Java 11 and later** through `java.net.http`, under the same TLS, certificate, deadline, size and redirect rules.

### Known limitations

- **PATCH:**
  - In `1.0.0-jdk8`, it needs Java 11 or later; on Java 8 it fails with a clear error.
  - It can't go through a proxy that asks for a login, and it is refused when a SOCKS proxy or `jdk.httpclient.enableAllMethodRetry=true` is set.
- **No connection reuse:** every call opens a new TCP and TLS connection. TLS sessions do resume.
- **Tokens with no expiry:** when a token says nothing about its expiry (no JWT `exp`, no `expires_in`, as with Salesforce), it is kept until the service answers 401. Token introspection (RFC 7662) is planned.
- **Refresh tokens:** a token server that rotates them (Jira 3LO) isn't supported yet. The new refresh token isn't handed back to the caller.
- **No metadata discovery** (RFC 8414 or OpenID): the token URL is set directly.
- **No DPoP.** Okta turns "Require DPoP" on by default for new service apps, so turn it off there.
- **Per-host limit:** the limit of 32 concurrent requests per host is shared JVM-wide by all tenants.
- **Cookies:** a JVM-wide `CookieHandler` set by other code also sees the library's calls, because `HttpURLConnection` can't opt out. The library warns once when one is set.
