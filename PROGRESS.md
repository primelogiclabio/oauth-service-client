# Progress

Goal: Java library that makes outbound calls to OAuth-protected external services (DocuSign, Salesforce, Jira, ...) for backend code: the caller passes client info (per service and tenant, or global) and the endpoint and payload; the library gets the token, cached per (service, tenant) until shortly before it expires, and makes the request.

## Current focus
- (none)

## Next
- [ ] ClientInfo entity (service, tenant or GLOBAL, token URL, client id/secret or key, scopes/audience, grant, extra attributes) that the caller builds and passes to initialize()
- [ ] Check which grant each target needs: client_credentials, JWT bearer (DocuSign, Salesforce), refresh token with write-back of rotated tokens (Jira 3LO)
- [ ] Token cache keyed by (service, tenant): reuse until near expiry, one renewal per key at a time, expired entries evicted
- [ ] Token requests for the chosen grants, reusing oauth-connector's token request, retry and redaction code
- [ ] Public API: initialize(ClientInfo), request(endpoint, payload) and request(token, endpoint, payload) for a caller's own token, returning status, headers and body, close() via AutoCloseable for try-with-resources; token cache outlives the instance so closing doesn't drop tokens
- [ ] Outbound requests: attach the token, on a 401 renew the token once and retry, timeouts, Retry-After handling and caller-requested retries, https only
- [ ] Tests with a stub token server, live check against Keycloak
- [ ] README with DocuSign (per tenant) and Salesforce (global) examples

## Done (last 10)
- Set up repo: private GitHub repo, Apache-2.0, Maven build for Java 8 (--release 8 on 9+), CI on JDK 8/21 x Linux/Windows; tests pass locally and in CI (79e60f8)

## Decisions
- The library gets the token and makes the outbound request; the caller only supplies client info, endpoint and payload, because config belongs to the service and tenant
- Service client is AutoCloseable (initialize, request, close), so callers can use try-with-resources
- Coordinates io.primelogiclab:oauth-service-client, package io.primelogiclab.oauthclient, so it sits next to oauth-connector's io.primelogiclab.oauth without sharing a package
- endpoint is always a full URL; request(token, endpoint, payload) uses the caller's token as is: no cache, and a 401 goes back to the caller, not renewed
- request returns every HTTP answer, any status, for the caller to handle; only failures without an answer (connection, timeout, TLS, getting the token) raise exceptions
- A busy answer (429/503) with Retry-After is retried after that delay (capped); without it, it's returned unless the caller asked for retries
- Cache key is (service type, tenant) with tenant = GLOBAL for shared integrations, because some integrations are per tenant (DocuSign) and some shared (Salesforce)
- Java 8 and 21, the user's requirement (same as oauth-connector), so HTTP needs its own overall deadline code
- Caffeine 2.9.x for the token cache, because each token needs its own expiry (Guava has one per cache) and Caffeine 3 needs Java 11
- New project instead of slimming oauth-connector, because that one grew sign-in, multi-tenant IdP settings and msal4j this goal doesn't need

## Parking lot
- Dependabot config for Maven and GitHub Actions (noticed while planning the build setup)

## Gotchas
- oauth-connector (../oauth-connector) is frozen and only a source of code to copy; don't change it from here
- Caffeine 2.9.x is the last line for Java 8; verify it on JDK 21 in CI

## Related
- (none)
