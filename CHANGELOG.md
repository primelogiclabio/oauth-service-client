# Changelog

All notable changes to this library. Versions follow [Semantic Versioning](https://semver.org/): from 1.0.0 on, a change that breaks callers only comes with a new major version.

## Unreleased

### Changed

- **Where releases are published:** from 1.1.0 on, both flavors go to `https://repo.primelogiclab.io/releases` (public, no login) instead of Maven Central. Add that repository to your build (see the README's Install section). 1.0.0 stays on Maven Central.

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
