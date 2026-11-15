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
