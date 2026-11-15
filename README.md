# oauth-service-client

Java library for backend services that call OAuth-protected external APIs (DocuSign, Salesforce, Jira, ...): it gets and caches access tokens per service and tenant and makes the request.

> **Status: in progress, not released.** Token requests and the API below work, with the token renewed after a 401 and safe retries. The plan and design decisions are in [PROGRESS.md](PROGRESS.md).

## Use

```java
try (OAuthServiceClient service = new OAuthServiceClient()) {
    service.initialize(clientInfo);                         // client info for one service and tenant (or global)
    ServiceResponse created = service.post(url, json);      // also get(url), put(url, json), delete(url); url is a full https URL
    ServiceResponse mine = service.get(myToken, url);       // a token you already have
    ServiceResponse custom = service.request(ServiceRequest.put(url, json)
            .header("Accept", "application/json")
            .scopes("items.write"));                        // scopes for this call
}
```

- The library gets the access token, caches it per service, tenant, user and scopes until shortly before it expires, and makes the request.
- Every HTTP answer goes back to the caller, whatever its status; only failures without an answer (connection, timeout, TLS, getting the token) raise exceptions.
- `service.token()` gives the token itself, for response fields such as Salesforce's `instance_url`.
- When the service answers 401, the token is renewed once and the call sent again; a busy answer with `Retry-After` is retried after that pause.
- `OAuthServiceClient.builder()` sets the timeouts, retries and response size limit; `ServiceRequest.timeout(...)` sets one call's.
- `ClientInfo.allowedHost("*.my.salesforce.com")` keeps the token to the hosts you list; recommended when URLs come from responses.

## Examples

### DocuSign: one integration per tenant (JWT grant)

Before you start: an integration key, the RSA key pair DocuSign generated for it (its PKCS#1 PEM is fine), the ID (a GUID) of the user the app acts as, and that user's one-time consent (or an admin's). Until consent is given, the token request fails with an `OAuthServiceException` whose `getError()` is `consent_required`.

```java
ClientInfo docusign = ClientInfo.forTenant("docusign", tenantCode)
        .tokenUrl("https://account-d.docusign.com/oauth/token")     // account.docusign.com in production
        .grant(Grant.JWT_BEARER)
        .clientId(integrationKey)
        .signingKey(ClientKey.fromPem(rsaPrivateKeyPem))
        .subject(userId)                                            // the user the app acts as
        .assertionAudience("account-d.docusign.com")                // a bare host, no https://
        .assertionClaim("scope", "signature impersonation")         // DocuSign wants the scopes in the assertion
        .allowedHost("account-d.docusign.com", "*.docusign.net")    // userinfo, and the account's base URI
        .build();

try (OAuthServiceClient service = new OAuthServiceClient()) {
    service.initialize(docusign);
    // once per account, then keep it: the host the account's API is on (accounts[].base_uri)
    ServiceResponse userinfo = service.get("https://account-d.docusign.com/oauth/userinfo");
    String baseUri = ...;   // from userinfo.getBody(), with your JSON library
    ServiceResponse created = service.post(baseUri + "/restapi/v2.1/accounts/" + accountId + "/envelopes", envelopeJson);
}
```

- Each tenant gets its own `ClientInfo`, with its own user and account.
- A token lasts an hour; the library signs a new assertion for the next one. There's no refresh token.

### Salesforce: one integration for all tenants (JWT bearer flow)

Before you start: an external client app with the certificate for your key uploaded and its consumer key, and the integration user pre-authorized through a profile or permission set.

```java
ClientInfo salesforce = ClientInfo.global("salesforce")
        .tokenUrl("https://login.salesforce.com/services/oauth2/token")   // test.salesforce.com for a sandbox
        .grant(Grant.JWT_BEARER)
        .clientId(consumerKey)
        .signingKey(ClientKey.fromPem(privateKeyPem))
        .subject("integration@example.com")                               // the pre-authorized user
        .assertionAudience("https://login.salesforce.com")                // a full URL here
        .allowedHost("*.my.salesforce.com")                               // instance_url, sandboxes too
        .build();

try (OAuthServiceClient service = new OAuthServiceClient()) {
    service.initialize(salesforce);
    String api = service.token().getField("instance_url") + "/services/data/" + apiVersion;   // e.g. v62.0
    ServiceResponse accounts = service.get(api + "/query?q=" + URLEncoder.encode("SELECT Id, Name FROM Account", "UTF-8"));
    ServiceResponse created = service.post(api + "/sobjects/Account", "{\"Name\":\"Acme\"}");
}
```

- Salesforce sends no `expires_in`, so the token is kept until Salesforce answers 401; the library then renews it and sends the call again.
- No scopes go in the request: they come from the app's policies.
- Record updates use PATCH, which arrives before 1.0.0.

### Answers and errors

Every answer comes back as a `ServiceResponse`, whatever its status: check `getStatus()` and read `getBody()` (or `getBodyBytes()` for a PDF). A failure without an answer, such as a refused token request or a timeout, throws `OAuthServiceException`; `getError()` holds the OAuth error, for example `consent_required` or `invalid_grant`.

## Documentation

- [How the library works](docs/library-overview.md) ([HTML with diagrams](docs/library-overview.html)): grants, client authentication, the token cache, retries, errors and a `ClientInfo` for each example service.
- [Example services](docs/services.md): what each vendor needs, with sources.

## Requirements

Java 8 or later (built and tested on Java 8 and 21).

## Build

```bash
mvn verify
```

Any JDK from 8 up builds it; on JDK 9 and later the code is compiled with `--release 8`, so it can't use newer Java APIs by accident. CI builds and tests on JDK 8 and 21, on Linux and Windows.

## Live check against Keycloak

`KeycloakTokenTest` sends real token requests to a throwaway Keycloak: client credentials with the secret in a Basic header or the body, `private_key_jwt` with RSA and EC keys, mutual TLS, the JWT bearer grant (Keycloak's JWT Authorization Grant) and the refresh token grant. It also calls Keycloak's userinfo endpoint as a service: a revoked token is renewed after the 401, and a certificate-bound token works only with its client certificate. It uses the test realm in `src/test/keycloak` and the TLS fixtures in `src/test/resources/tls`; every secret there is a test value. Without `keycloak.https.url` the test is skipped.

Start Keycloak (on Windows in Git Bash, put `MSYS_NO_PATHCONV=1` in front):

```bash
docker run -d --name oauth-service-client-it-keycloak -p 127.0.0.1:8182:8080 -p 127.0.0.1:8445:8443 -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin -v "$(pwd)/src/test/keycloak:/opt/keycloak/data/import:ro" -v "$(pwd)/src/test/resources/tls:/opt/keycloak/conf/tls:ro" quay.io/keycloak/keycloak:26.8.1 start-dev --import-realm --features=jwt-authorization-grant --https-certificate-file=/opt/keycloak/conf/tls/server.crt --https-certificate-key-file=/opt/keycloak/conf/tls/server.key --https-trust-store-file=/opt/keycloak/conf/tls/ca-truststore.p12 --https-trust-store-password=changeit --https-client-auth=request
```

Run the build with the check, once Keycloak answers on port 8182:

```bash
mvn verify -Dkeycloak.https.url=https://localhost:8445
```

Remove the container afterwards:

```bash
docker rm -f oauth-service-client-it-keycloak
```

## License

Apache License 2.0; see [LICENSE](LICENSE) and [NOTICE](NOTICE).
