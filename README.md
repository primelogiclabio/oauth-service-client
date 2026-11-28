# oauth-service-client

Java library for backend services that call OAuth-protected external APIs (DocuSign, Salesforce, Jira, ...): it gets and caches access tokens per service and tenant and makes the request.

## Install

The library comes in two flavors with the same API. Pick the one for the Java version your app runs on:

| Your app runs on | Version | Built for | Brings along |
|---|---|---|---|
| Java 21 or later | `1.1.0` | Java 21 | Caffeine 3 |
| Java 8 to 20 | `1.1.0-jdk8` | Java 8 | Caffeine 2.9 |

Versions from 1.1.0 on are published to `https://repo.primelogiclab.io/releases`, which needs no login; 1.0.0 is on Maven Central only.

Maven:

```xml
<repositories>
    <repository>
        <id>primelogiclab-releases</id>
        <url>https://repo.primelogiclab.io/releases</url>
        <snapshots><enabled>false</enabled></snapshots>
    </repository>
</repositories>

<dependency>
    <groupId>io.primelogiclab</groupId>
    <artifactId>oauth-service-client</artifactId>
    <version>1.1.0</version> <!-- 1.1.0-jdk8 on Java 8 to 20 -->
</dependency>
```

Gradle:

```groovy
repositories {
    mavenCentral()
    maven { url 'https://repo.primelogiclab.io/releases' }
}

dependencies {
    implementation 'io.primelogiclab:oauth-service-client:1.1.0' // 1.1.0-jdk8 on Java 8 to 20
}
```

When you update, keep the `-jdk8` suffix if you have it: a version without it needs Java 21.

## Use

```java
try (OAuthServiceClient service = new OAuthServiceClient()) {
    service.initialize(clientInfo);                         // client info for one service and tenant (or global)
    ServiceResponse created = service.post(url, json);      // also get, put, patch, delete; url is a full https URL
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
- At most 32 calls are in flight to one host at once in the JVM, for all tenants, and further calls wait their turn; `OAuthServiceClient.setMaxRequestsPerHost(n)` changes that.
- `ClientInfo.allowedHost("*.my.salesforce.com")` keeps the token to the hosts you list; recommended when URLs come from responses.
- `ClientInfo.signingAlgorithm("PS256")` signs with RSASSA-PSS, as Entra ID recommends for certificate credentials; an RSA key signs RS256 otherwise.
- Instead of `tokenUrl(...)`, `ClientInfo.issuer(...)` reads the token endpoint from the server's metadata (OpenID Connect discovery or RFC 8414), kept for a day; `metadataUrl(...)` names the document when it's elsewhere:

```java
ClientInfo graph = ClientInfo.global("graph")
        .issuer("https://login.microsoftonline.com/" + directoryId + "/v2.0")  // must match the document's issuer exactly
        .clientId(applicationId)
        .clientSecret(secret)
        .scope("https://graph.microsoft.com/.default")
        .build();
```

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
    ServiceResponse updated = service.patch(api + "/sobjects/Account/" + accountId, "{\"Phone\":\"555-0100\"}");
}
```

- Salesforce sends no `expires_in`, so the token is kept until Salesforce answers 401; the library then renews it and sends the call again.
- No scopes go in the request: they come from the app's policies.
- Record updates use PATCH, which needs Java 11 or later (see Requirements).

### Answers and errors

Every answer comes back as a `ServiceResponse`, whatever its status: check `getStatus()` and read `getBody()` (or `getBodyBytes()` for a PDF). A failure without an answer, such as a refused token request or a timeout, throws `OAuthServiceException`; `getError()` holds the OAuth error, for example `consent_required` or `invalid_grant`.

## Documentation

- [How the library works](docs/library-overview.md) ([HTML with diagrams](docs/library-overview.html)): grants, client authentication, the token cache, retries, errors and a `ClientInfo` for each example service.
- [Example services](docs/services.md): what each vendor needs, with sources.
- [Changelog](CHANGELOG.md): what each version holds, and the known limitations.
- Javadoc: `mvn package` writes it to `target/reports/apidocs`; it is published with each release.

## Requirements

- `1.1.0` needs Java 21 or later.
- `1.1.0-jdk8` runs on Java 8 or later. Its PATCH needs Java 11 or later: it is sent with Java's `java.net.http` client, since `HttpURLConnection` can't send it; on Java 8 it fails with a clear error.

## Build

```bash
mvn verify          # the Java 21 flavor, on JDK 21
mvn verify -Pjdk8   # the Java 8 flavor, on JDK 11 or later
```

Both flavors build from the same source, which stays within Java 8. On JDK 9 and later each is compiled with `--release` for its Java version, so it can't use newer Java APIs by accident. JDK 8 itself builds only the Java 8 flavor, picked automatically, and without PATCH. Releases are built on JDK 21 by the release workflow when a `vX.Y.Z` tag is pushed. CI builds and tests the Java 8 flavor on JDK 8 and 21 and the Java 21 flavor on JDK 21, on Linux and Windows.

## Live check against Keycloak

`KeycloakTokenTest` sends real token requests to a throwaway Keycloak: client credentials with the secret in a Basic header or the body, `private_key_jwt` with RSA keys (RS256, and PS256 where the client requires it) and EC keys, mutual TLS, the JWT bearer grant (Keycloak's JWT Authorization Grant) and the refresh token grant. It also calls Keycloak's userinfo endpoint as a service: a revoked token is renewed after the 401, and a certificate-bound token works only with its client certificate. It uses the test realm in `src/test/keycloak` and the TLS fixtures in `src/test/resources/tls`; every secret there is a test value. Without `keycloak.https.url` the test is skipped.

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
