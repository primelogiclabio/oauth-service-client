# Example services: grants and client authentication

What each example service needs from a backend that calls it with no user present. The library implements the standards (RFC 6749 client credentials and refresh token, RFC 7523 JWT bearer and private_key_jwt, RFC 8705 mutual TLS) and common practice, and expects every identity provider to support them. Where a vendor differs in detail, a generic setting covers it (`tokenParameter`, `assertionAudience`, `assertionClaim`, `clientSecretInBody`); there is no per-vendor code. Checked against the vendors' public docs on 2026-11-14; links follow each section.

## Summary

| Service | Grant | Client authentication | Token URL | Watch out for |
|---|---|---|---|---|
| DocuSign eSignature | JWT bearer | none (the assertion is the proof) | `https://account[-d].docusign.com/oauth/token` | scope goes in the assertion's `scope` claim; `aud` is a bare host; one-time user consent; base URI from `/oauth/userinfo` |
| Salesforce | JWT bearer | none | `https://{login,test,MyDomain}.salesforce.com/services/oauth2/token` | no `expires_in` in the response; `instance_url` needed for API calls; no scopes in the request |
| Salesforce (alternative) | client_credentials | secret, Basic header or body | My Domain host only | same as above; run-as integration user |
| Jira Cloud, 3LO app | refresh_token | secret in a JSON body | `https://auth.atlassian.com/oauth/token` | rotating refresh tokens: store the new one every time; JSON body is the only documented form |
| Jira Cloud, service account | client_credentials | secret in a form body | `https://auth.atlassian.com/oauth/token` | API via `api.atlassian.com/ex/jira/{cloudId}`; no scope parameter |
| Vertex Payroll Tax | client_credentials | secret, Basic header or body (docs show both) | `https://auth.vertexcloud.com/oauth/token` | `audience=verx://migration-api` required; scope picks prod or test; 10 token requests per 8 hours |
| Microsoft Entra ID | client_credentials | secret (Basic or body) or certificate via private_key_jwt | `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token` | scope `{resource}/.default`; assertion header `x5t#S256`, PS256 recommended |
| Okta | client_credentials | secret (Basic default, or body) or private_key_jwt; Okta API scopes need private_key_jwt | `https://{domain}/oauth2/v1/token` (org) or `/oauth2/{id}/v1/token` (custom) | DPoP is on by default for new service apps; `jti` can be used once |
| Auth0 | client_credentials | secret (the default), private_key_jwt or mTLS (Enterprise plans) | `https://{tenant}.auth0.com/oauth/token` or the custom domain | `audience` (the API identifier) as a form field; assertion `aud` is the tenant URL with a trailing slash; assertion lifetime at most 5 minutes |
| Oracle Integration (OIC) | client_credentials, or JWT bearer user assertion | secret in a Basic header, or private_key_jwt | `https://idcs-{id}.identity.oraclecloud.com/oauth2/v1/token` | assertion header needs `x5t` or `kid`; `aud` is the identity domain URL; scope `https://{oic-host}:443urn:opc:resource:consumer::all` |

## DocuSign eSignature: JWT Grant

- POST form `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`, `assertion`. No client secret.
- Assertion: header `alg` RS256 (RSA SHA-256 only), `typ` JWT. Claims `iss` integration key, `sub` user ID GUID, `aud` `account-d.docusign.com` or `account.docusign.com` ("Do not include `https://`"), `iat`, `exp`, and `scope`, e.g. `signature impersonation`.
- Response has `expires_in` (one hour). No refresh token: sign a new assertion.
- Setup: integration key, RSA key pair, one-time individual or admin consent (`consent_required` until then).
- API base: `GET /oauth/userinfo` on the auth host gives `accounts[].base_uri`; calls go to `{base_uri}/restapi/v2.1/accounts/{account_id}`. DocuSign says to cache it.
- Sources: [JWT get token](https://developers.docusign.com/platform/auth/jwt-get-token/), [JWT overview](https://developers.docusign.com/platform/auth/jwt/), [userinfo](https://developers.docusign.com/platform/auth/reference/user-info/), [scopes](https://developers.docusign.com/platform/auth/reference/scopes/)

## Salesforce

- JWT bearer: POST form `grant_type=…jwt-bearer`, `assertion`; no client secret. Header `alg` RS256 (required). Claims `iss` consumer key, `sub` username, `aud` `https://login.salesforce.com` or `https://test.salesforce.com` (full URL), `exp` within 3 minutes; optional `jti`, rejected if reused. No scope in the request: scopes come from the app's policies.
- Client credentials: My Domain host only. Secret in a Basic header ("more secure") or in the body. No scopes in the request. Run-as integration user set on the app.
- Response (both): `access_token`, `instance_url`, `id`, `token_type`, `scope`; **no `expires_in`**. Lifetime is the session timeout from the app, profile or org settings. No refresh token.
- Setup (JWT): certificate on the external client app; users pre-authorized by profile or permission set.
- Sources: [JWT bearer flow](https://help.salesforce.com/s/articleView?id=xcloud.remoteaccess_oauth_jwt_flow.htm&type=5), [client credentials flow](https://help.salesforce.com/s/articleView?id=xcloud.remoteaccess_oauth_client_credentials_flow.htm&type=5), [endpoints](https://help.salesforce.com/s/articleView?id=xcloud.remoteaccess_oauth_endpoints.htm&type=5), [errors](https://help.salesforce.com/s/articleView?id=xcloud.remoteaccess_oauth_flow_errors.htm&type=5), [access tokens](https://help.salesforce.com/s/articleView?id=xcloud.remoteaccess_access_tokens.htm&type=5)

## Jira Cloud (Atlassian)

- 3LO app: after one-time user consent (with `offline_access`), POST JSON `grant_type=refresh_token`, `client_id`, `client_secret`, `refresh_token`. Every refresh returns a new refresh token and disables the one used; reuse within 10 minutes is tolerated. Refresh tokens lapse after 90 days unused; no absolute expiry since 2023 (staff forum post). Form encoding isn't documented for this call.
- Service account (2LO): POST form `grant_type=client_credentials`, `client_id`, `client_secret`; scopes are fixed when the admin creates the credential. Token valid 60 minutes, no refresh token. Needs centralized user management; 5 service accounts free per org, more with Atlassian Guard.
- API base: `https://api.atlassian.com/ex/jira/{cloudId}/rest/api/…`; cloud ID from `accessible-resources` (3LO) or `https://{site}.atlassian.net/_edge/tenant_info`.
- Connect and Forge don't fit a plain backend (Connect ends 31 January 2027).
- Sources: [3LO apps](https://developer.atlassian.com/cloud/jira/platform/oauth-2-3lo-apps/), [refresh tokens](https://developer.atlassian.com/cloud/oauth/getting-started/refresh-tokens), [service account credentials](https://support.atlassian.com/user-management/docs/create-oauth-2-0-credential-for-service-accounts/), [service accounts](https://support.atlassian.com/user-management/docs/understand-service-accounts/), [cloud ID](https://support.atlassian.com/jira/kb/retrieve-my-atlassian-sites-cloud-id/), [persistent refresh token deprecation (forum)](https://community.developer.atlassian.com/t/updated-31-january-2022-action-required-deprecating-persistent-refresh-tokens/54172)

## Vertex Payroll Tax (Vertex Inc.)

- POST form `grant_type=client_credentials`, `client_id`, `client_secret`, `audience=verx://migration-api`, `scope` = `payroll-calculation`, `payroll-addr-cleanse` or their `-test` forms. The page lists the secret as a body field and also shows a Basic header; the Postman guide uses Basic.
- "up to 10 access token requests … every 8 hours" by default: the token must be cached and shared. The example `expires_in` is 1200 s, which would need more than 10 renewals in 8 hours; check the real lifetime with a live call.
- O Series Cloud uses the same token URL and `audience` without a scope; its legacy `auth.vertexsmb.com` endpoint shut down in November 2025.
- Sources: [access token](https://developer.vertexinc.com/payroll/docs/access-token), [Postman setup](https://developer.vertexinc.com/payroll/docs/configuring-postman-to-work-with-vertex-payroll-tax), [O Series cloud auth](https://developer.vertexinc.com/oseries/docs/authentication-cloud)

## Microsoft Entra ID

- POST form `grant_type=client_credentials`, `client_id`, `scope` = `{App ID URI}/.default` (one resource only), and either `client_secret` (body or Basic header) or `client_assertion_type` + `client_assertion`.
- Certificate credential: header `alg` "Should be PS256", `typ` JWT, `x5t#S256`; the page's example still uses RS256 with `x5t`. Claims `aud` = the token URL, `iss` = `sub` = client ID, `jti`, `nbf`, `iat`, `exp` 5 to 10 minutes. Only uploaded certificates, no bare keys.
- Response has `expires_in` (60 to 90 minutes); no refresh token. Setup: application permissions with admin consent.
- mTLS client authentication and DPoP aren't offered for this flow.
- Sources: [client credentials flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow), [certificate credentials](https://learn.microsoft.com/en-us/entra/identity-platform/certificate-credentials), [access tokens](https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens)

## Okta

- Org authorization server (`/oauth2/v1/token`) issues `okta.*` scopes for Okta's own API, and only with private_key_jwt. Custom authorization servers (`/oauth2/{id}/v1/token`) issue custom scopes for your own APIs and accept secrets too.
- Client authentication is one method per app: `client_secret_basic` (default), `client_secret_post`, `client_secret_jwt`, `private_key_jwt`, or mTLS (early access).
- Assertion: RS256/384/512 or ES256/384/512; `aud` = full token URL; `iss` = `sub` = client ID; `exp` at most one hour ahead; a `jti` can be used once. Keys are bare JWKS keys with a `kid`.
- Response has `expires_in` (one hour on the org server, policy-set on custom servers); no refresh token.
- DPoP: "Require DPoP header in token requests" is enabled by default when a service app is created (Okta support article). With it on, every token and API request needs a signed proof JWT, a nonce round trip and `Authorization: DPoP`.
- Sources: [service app guide](https://developer.okta.com/docs/guides/implement-oauth-for-okta-serviceapp/main/), [client authentication](https://developer.okta.com/docs/api/openapi/okta-oauth/guides/client-auth/), [client credentials](https://developer.okta.com/docs/guides/implement-grant-type/clientcreds/main/), [authorization servers](https://developer.okta.com/docs/concepts/auth-servers/), [DPoP](https://developer.okta.com/docs/guides/dpop/oktaresourceserver/main/), [DPoP default (support KB)](https://support.okta.com/help/s/article/receiving-use-dpop-nonce-error-when-requesting-access-token)

## Auth0

- POST `grant_type=client_credentials`, `client_id`, `client_secret`, `audience` = the API's identifier (sent as a token parameter), optional `organization`.
- Client authentication: client secret is the default; Private Key JWT needs an Enterprise plan; mTLS needs Enterprise with the Highly Regulated Identity add-on and a custom domain. Whether an app set to body or Basic rejects the other form is not stated.
- Private Key JWT assertion: `alg` as registered with the credential (RS256, RS384 or PS256), optional `kid`; `iss` = `sub` = client ID; `aud` = `https://{tenant}.auth0.com/` or the custom domain, "Include the trailing slash"; `exp` at most 5 minutes ahead (1 minute recommended); `jti` unique (one-time use); assertion at most 2048 bytes.
- Response has `expires_in` (example 86400); no refresh token.
- Sources: [client credentials flow](https://auth0.com/docs/get-started/authentication-and-authorization-flow/client-credentials-flow/call-your-api-using-the-client-credentials-flow), [Private Key JWT](https://auth0.com/docs/get-started/authentication-and-authorization-flow/authenticate-with-private-key-jwt), [application credentials](https://auth0.com/docs/secure/application-credentials)

## Oracle Integration (OIC)

- Tokens from the OCI IAM identity domain: POST form to `https://idcs-{id}.identity.oraclecloud.com/oauth2/v1/token`.
- Client credentials: `grant_type=client_credentials`, `scope`, secret in a Basic header (the only form OIC's docs show).
- JWT user assertion (marked recommended): `grant_type=…jwt-bearer`, `assertion`, `scope`, client authenticated with its secret. Assertions (user or client): RS256; header must carry `x5t` (SHA-1 thumbprint) or `kid` (certificate alias); `aud` must include the identity domain URL; `exp` required.
- Scope: `https://{oic-host}:443urn:opc:resource:consumer::all`, no separator before `urn:`; copy the exact value from the app's token issuance policy.
- Response has `expires_in` (3600); refresh token only with `offline_access`.
- Setup: confidential application with the grant enabled, OIC scopes added, app activated (created deactivated), ServiceInvoker role on the OIC instance.
- OIC's own REST connections offer, as outbound security policies: Basic, client credentials (secret as Basic header or in the body, form or JSON body), ROPC, authorization code with PKCE, custom two- and three-legged flows, JWT client assertion, JWT user assertion, API key, OAuth 1.0, OCI and AWS signatures. Two-way SSL is a connection property.
- Sources: [invoking OIC integrations](https://docs.oracle.com/en/cloud/paas/application-integration/rest-adapter/authenticate-requests-invoking-oic-integration-flows.html), [client credentials for OIC APIs](https://docs.oracle.com/en/cloud/paas/application-integration/integrations-user/call-developer-apis-client-credentials.html), [client assertion](https://docs.oracle.com/en-us/iaas/Content/Identity/api-getstarted/ClientAssertion.htm), [confidential application](https://docs.oracle.com/en-us/iaas/Content/Identity/applications/add-confidential-application.htm), [REST connection security](https://docs.oracle.com/en/cloud/paas/application-integration/rest-adapter/create-connection.html), [JWT assertion for outbound calls](https://docs.oracle.com/en/cloud/paas/application-integration/rest-adapter/jwt-assertion-support-outbound-invocations.html)

## What this means for the library

- Client secret: sent as an HTTP Basic header (RFC 6749's must-support method, Okta's default, OIC's only form) or in the body (Atlassian), so it needs a setting.
- JWT bearer scope: a form field (OIC), an assertion claim (DocuSign) or nothing (Salesforce).
- Assertion header: `kid` when the key has one; `x5t#S256` and `x5t` when it has a certificate (Entra, OIC). RS256 for RSA keys everywhere; ES256 for EC keys where accepted (Okta).
- Assertions are short-lived (exp about a minute ahead; Auth0 allows at most 5 minutes, Salesforce 3) with a fresh `jti` every time (Okta, Salesforce and Auth0 allow one use).
- `aud` is free text: a bare host (DocuSign), a site URL (Salesforce), the token URL (Entra, Okta), the tenant URL with a trailing slash (Auth0), the identity domain URL (OIC).
- Token response: `expires_in` may be missing and the token opaque (Salesforce), so its expiry comes from token introspection (RFC 7662; Salesforce: `/services/oauth2/introspect`); extra fields such as `instance_url` must reach the caller.
- Token requests are rate-limited at some vendors (Vertex: 10 per 8 hours), so renew only near expiry and share the cache.
- Jira: the library targets service accounts (client_credentials) first; 3LO refresh-token rotation, which needs each new refresh token handed back to the caller, comes later.
- Not in scope: DPoP (Okta default for new service apps; it can be turned off on the app), API keys, OAuth 1.0, request signing (OCI, AWS), ROPC.
