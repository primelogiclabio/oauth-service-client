# Progress

Goal: Java library that makes outbound calls to OAuth-protected external services (e.g. DocuSign, Salesforce, Jira, Vertex payroll, Entra ID apps, Okta apps, Auth0, Oracle Integration (OIC)) for backend code: the caller passes client info (per service and tenant, or global) and the endpoint and payload; the library gets the token, cached per (service, tenant, scopes) until shortly before it expires, and makes the request. Basic first (token requests, public API, outbound requests, tests, README), then features on top.

## Current focus
- (none)

## Next
- [ ] Public API: initialize(ClientInfo), request(endpoint, payload) and request(token, endpoint, payload) for a caller's own token, returning status, headers and body, close() via AutoCloseable for try-with-resources; token cache outlives the instance so closing doesn't drop tokens; expose token response fields the caller needs (Salesforce instance_url); optional scopes argument on request(...) (the app's scopes replace ClientInfo's for that call)
- [ ] Outbound requests: attach the token, on a 401 renew the token once and retry, timeouts, Retry-After handling and caller-requested retries, https only; cache the mTLS socket factory per client key (built per token request for now)
- [ ] Tests for outbound requests with the stub server, and their live check against Keycloak (token requests are covered: TokenClientTest, KeycloakTokenTest)
- [ ] README with DocuSign (per tenant) and Salesforce (global) examples
- [ ] Refresh token rotation for 3LO apps (Jira): hand each rotated refresh token back to the caller to store; JSON token request body (Atlassian documents only JSON there)
- [ ] Short cool-down after a failed token request, so repeated failures don't use up a vendor's request cap (Vertex: 10 per 8 hours)
- [ ] Introspection (RFC 7662, ClientInfo.introspectionUrl) for a token with no JWT exp and no expires_in (Salesforce), then AccessToken.withExpiryFrom; Salesforce's introspect endpoint takes client_id and client_secret (Basic or body), so with JWT bearer the secret authenticates the token request too: check Salesforce accepts that
- [ ] Metadata discovery: issuer or metadata URL in ClientInfo instead of tokenUrl; read the server's metadata (RFC 8414 / OpenID discovery) for the token and introspection endpoints and supported client authentication, reusing oauth-connector's MetadataResolver (TokenClient.tokenUrl is the one place to plug it in)
- [ ] Vendor clients (DocuSign, Salesforce, Jira, Vertex, Entra ID, Okta, Auth0, OIC) as features on top of the generic core
- [ ] PS256 signing setting: Entra ID recommends PS256 for certificate credentials (RS256 still accepted)

## Done (last 10)
- Token requests: TokenClient for client credentials, JWT bearer and refresh token; secret in Basic header or body, private_key_jwt (RS256, ES256/384/512), mTLS or none; resent only when not processed; OAuthServiceException; the app's scopes in the cache key; KeycloakTokenTest live check; docs/library-overview.md and .html; tests pass on JDK 8 and 21 with Keycloak (127), 13 mutation checks caught (3028fd6)
- Token cache: TokenCache per (service, tenant) on Caffeine 2.9.3 (one renewal per key, renewed 5 minutes before expiry, expired entries evicted, renew() after a 401) and AccessToken (expiry from JWT exp, expires_in or introspection via the new ClientInfo.introspectionUrl); tests pass on JDK 8 and 21, 24 mutation checks caught
- Checked grant and client authentication for all 8 example services (docs/services.md, sourced): ClientInfo gained clientSecretInBody (CLIENT_SECRET_BASIC/POST) and assertionClaim; behaviour gaps noted on Next items; tests pass on JDK 8 and 21, 8 mutation checks caught
- ClientInfo entity: ClientInfo (forTenant/global builder, every problem reported at once, secrets masked), ClientKey (PEM or keystore, optional kid) and Grant; tests pass on JDK 8 and 21, 14 mutation checks caught
- Set up repo: private GitHub repo, Apache-2.0, Maven build for Java 8 (--release 8 on 9+), CI on JDK 8/21 x Linux/Windows; tests pass locally and in CI (79e60f8)

## Decisions
- The library gets the token and makes the outbound request, the caller supplying only client info, a full-URL endpoint and payload, because config belongs to the service and tenant; AutoCloseable (initialize, request, close) for try-with-resources; request returns every HTTP answer, any status, and only failures without an answer (connection, timeout, TLS, getting the token) throw; request(token, endpoint, payload) uses the caller's token as is: no cache, a 401 goes back to the caller
- A busy answer (429/503) with Retry-After is retried after that delay (capped); without it, it's returned unless the caller asked for retries
- Cache key is (service type, tenant, scope set), because some integrations are per tenant (DocuSign) and some shared (Salesforce), and tokens for different scopes must not replace each other; global is a flag (getTenant() null, isGlobal()), not a "GLOBAL" tenant string, so a real tenant coded GLOBAL can't collide
- Java 8 and 21, the user's requirement (same as oauth-connector), so HTTP needs its own overall deadline code and the token cache uses Caffeine 2.9.x (each token needs its own expiry, Guava has one per cache, Caffeine 3 needs Java 11)
- New project io.primelogiclab:oauth-service-client (package io.primelogiclab.oauthclient, next to oauth-connector's io.primelogiclab.oauth without sharing it) instead of slimming oauth-connector, because that one grew sign-in, multi-tenant IdP settings and msal4j this goal doesn't need
- The core stays generic: it implements the standards (RFC 6749, 7523, 8705) and common practice, and vendor differences go through generic settings (tokenParameter, assertionAudience, assertionClaim, clientSecretInBody); vendor-specific clients are a separate layer on top, built later
- ClientKey (key, optional chain, optional kid) serves as signingKey (JWT bearer assertion or private_key_jwt) or clientCertificate (mutual TLS), because "certificate instead of secret" means private_key_jwt at Entra/Okta and mTLS elsewhere
- Client authentication follows from what's set: signing key outside JWT bearer = private_key_jwt, else secret (HTTP Basic header by default, because it's RFC 6749's must-support method, Okta's default and OIC's only form; body with clientSecretInBody(true), as Atlassian wants), else certificate alone = mTLS, else none
- Extra JWT claims are caller-set strings (assertionClaim), because DocuSign wants scope inside the assertion; iss, sub, aud, exp, iat, nbf, jti stay library-set; attributes (caller data, never sent) are separate from tokenParameters (sent; reserved names like grant_type, scope rejected)
- Jira targets Atlassian service accounts (client_credentials) first; rotated refresh-token write-back gets its own later item
- Token URL https only, no loopback exception; tests use an HTTPS stub with the test CA
- PEM input kept (PemKeys copied), because vendors hand out PEM and the JDK can't read PKCS#1 (DocuSign's format)
- Token expiry: JWT exp first (moved back when iat shows the token server's clock ahead; a past iat is left alone, as a server may hand out an earlier token), then expires_in, then introspection (RFC 7662); no guessed lifetime, a token with none is kept until a 401, because the JWT's exp is what the service checks
- Renew 5 minutes before expiry (at half the lifetime for tokens under 10 minutes), so a nearly expired token isn't sent and the call made twice; one renewal per key through a map of in-flight futures, not Caffeine's compute, which would block other keys during a slow token request; waiters share the result or failure, except an interrupted renewal's
- A cached token is reused only while the settings that shape it match (token URL, grant, client ID, subject, audience, claims, scopes, parameters, client certificate); rotated secrets, keys and refresh tokens keep it
- Scopes: the app may pass scopes per request, which replace ClientInfo's defaults for that token, because often only the app knows them
- Token requests are resent only when the server certainly didn't process them (no connection, 429, 503 with Retry-After; at most 2 retries in one 60 s deadline), because of vendor caps (Vertex) and rotating refresh tokens; a refresh request is also not resendable by the JDK; a failed TLS handshake is never retried, as it fails the same way again
- JWT bearer without client authentication sends only grant_type and assertion (no client_id), as DocuSign and Salesforce document; the assertion's iss names the client
- Failures without a usable answer throw OAuthServiceException (public, unchecked; OAuth error, description, URI and HTTP status, -1 when none); HTTP plumbing stays package-private until the public API item

## Parking lot
- Dependabot config for Maven and GitHub Actions (noticed while planning the build setup)
- DPoP (proof JWT per request, nonce retry): out of scope for now; Okta turns "Require DPoP" on by default for new service apps, so it must be turned off there

## Gotchas
- oauth-connector (../oauth-connector) is frozen and only a source of code to copy; don't change it from here
- .gitignore ignores *.key and *.p12 except src/test/resources/tls; regenerate those fixtures with its generate.sh (openssl + keytool), valid until 2036-11
- docs/services.md holds vendor facts checked 2026-11-14; recheck the linked vendor page before relying on a detail
- Vertex Payroll's example expires_in is 1200 s, yet token requests are capped at 10 per 8 hours: check the real lifetime in a live call
- Caffeine evicts variable-expiry entries in buckets of about a second: reads check expiry exactly, but size() can lag
- Keycloak live check: throwaway container oauth-service-client-it-keycloak (README); its JWT bearer grant needs --features=jwt-authorization-grant and a URL issuer, so that test client's ID is a URL
- With TLS 1.3 a server refusing the client certificate does so after the handshake, so the client sees a write error, not an SSLHandshakeException

## Related
- (none)
