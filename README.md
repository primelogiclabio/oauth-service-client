# oauth-service-client

Java library for backend services that call OAuth-protected external APIs (DocuSign, Salesforce, Jira, ...): it gets and caches access tokens per service and tenant and makes the request.

> **Status: planning.** Nothing is usable yet; the plan and design decisions are in [PROGRESS.md](PROGRESS.md).

## Planned use

```java
try (OAuthServiceClient service = ...) {
    service.initialize(clientInfo);                    // client info for one service and tenant (or global)
    Response response = service.request(endpoint, payload);   // endpoint is a full URL
}
```

- The library gets the access token, caches it per service and tenant until shortly before it expires, and makes the request.
- A caller that already has a token can pass it: `request(token, endpoint, payload)`.
- Every HTTP answer goes back to the caller, whatever its status; only failures without an answer (connection, timeout, TLS, getting the token) raise exceptions.

## Requirements

Java 8 or later (built and tested on Java 8 and 21).

## License

Apache License 2.0; see [LICENSE](LICENSE) and [NOTICE](NOTICE).
