package io.primelogiclab.oauthclient;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * How to get tokens for one external service, for one tenant or for all tenants (global). The caller
 * builds it from its own configuration and passes it to the service client. Immutable and thread-safe.
 *
 * <pre>{@code
 * ClientInfo docusign = ClientInfo.forTenant("docusign", "acme")
 *         .tokenUrl("https://account-d.docusign.com/oauth/token")
 *         .grant(Grant.JWT_BEARER)
 *         .clientId(integrationKey)
 *         .signingKey(ClientKey.fromPem(rsaPrivateKeyPem))
 *         .subject(userId)
 *         .assertionAudience("account-d.docusign.com")
 *         .scope("signature", "impersonation")
 *         .attribute("accountId", accountId)
 *         .build();
 *
 * ClientInfo graph = ClientInfo.global("graph")
 *         .tokenUrl("https://login.microsoftonline.com/" + directoryId + "/oauth2/v2.0/token")
 *         .clientId(applicationId)
 *         .signingKey(ClientKey.fromKeyStore(pkcs12, password))  // certificate credential
 *         .scope("https://graph.microsoft.com/.default")
 *         .build();
 * }</pre>
 *
 * <p>How the client proves itself to the token endpoint follows from what is set: a {@link #getSigningKey()
 * signing key} (outside the JWT bearer grant) means a {@code private_key_jwt} client assertion, else a
 * {@link #getClientSecret() client secret}, else a {@link #getClientCertificate() client certificate} alone
 * means mutual TLS (RFC 8705). A client certificate set together with a secret or signing key is still
 * presented in the TLS handshake.
 *
 * <p>{@link #getAttributes() Attributes} are the caller's own data (an account ID, a base URL) and are never
 * sent anywhere; {@link #getTokenParameters() token parameters} are sent as extra form fields in the token request.
 */
public final class ClientInfo {

    /** How the client authenticates to the token endpoint, derived from what was set. */
    enum ClientAuthentication {
        /** Only {@code client_id} is sent (public client), or the JWT bearer assertion is the only proof. */
        NONE,
        /** {@code client_secret}. */
        CLIENT_SECRET,
        /** A JWT client assertion signed with the signing key (RFC 7523 section 2.2). */
        PRIVATE_KEY_JWT,
        /** The client certificate in the TLS handshake (RFC 8705), with {@code client_id} in the body. */
        MUTUAL_TLS
    }

    /** Form fields the library sets itself; a token parameter may not override them. */
    static final Set<String> RESERVED_TOKEN_PARAMETERS = Collections.unmodifiableSet(new HashSet<String>(Arrays.asList(
            "grant_type", "client_id", "client_secret", "client_assertion", "client_assertion_type",
            "assertion", "refresh_token", "scope")));

    private final String service;
    private final String tenant;
    private final String tokenUrl;
    private final Grant grant;
    private final String clientId;
    private final String clientSecret;
    private final ClientKey signingKey;
    private final ClientKey clientCertificate;
    private final String subject;
    private final String assertionAudience;
    private final String refreshToken;
    private final List<String> scopes;
    private final Map<String, String> tokenParameters;
    private final Map<String, String> attributes;

    private ClientInfo(Builder b, List<String> scopes, Map<String, String> tokenParameters, Map<String, String> attributes) {
        this.service = b.service;
        this.tenant = b.global ? null : b.tenant;
        this.tokenUrl = b.tokenUrl;
        this.grant = b.grant;
        this.clientId = b.clientId;
        this.clientSecret = b.clientSecret;
        this.signingKey = b.signingKey;
        this.clientCertificate = b.clientCertificate;
        this.subject = b.subject;
        this.assertionAudience = b.assertionAudience;
        this.refreshToken = b.refreshToken;
        this.scopes = scopes;
        this.tokenParameters = tokenParameters;
        this.attributes = attributes;
    }

    /** Client info for one tenant of a service, e.g. a DocuSign account per customer. */
    public static Builder forTenant(String service, String tenant) {
        return new Builder(service, tenant, false);
    }

    /** Client info shared by all tenants of a service, e.g. one Salesforce integration for everyone. */
    public static Builder global(String service) {
        return new Builder(service, null, true);
    }

    /** The service type as the caller names it, e.g. {@code docusign}. */
    public String getService() {
        return service;
    }

    /** The tenant code, or {@code null} when {@link #isGlobal() global}. */
    public String getTenant() {
        return tenant;
    }

    /** True when this client info is shared by all tenants. */
    public boolean isGlobal() {
        return tenant == null;
    }

    public String getTokenUrl() {
        return tokenUrl;
    }

    public Grant getGrant() {
        return grant;
    }

    public String getClientId() {
        return clientId;
    }

    /** The client secret, or {@code null}. */
    public String getClientSecret() {
        return clientSecret;
    }

    /** Signs the JWT bearer grant's assertion, or the {@code private_key_jwt} client assertion with other grants; or {@code null}. */
    public ClientKey getSigningKey() {
        return signingKey;
    }

    /** Presented in mutual TLS to the token endpoint; or {@code null}. */
    public ClientKey getClientCertificate() {
        return clientCertificate;
    }

    /** The JWT bearer assertion's {@code sub}, e.g. a DocuSign user ID or Salesforce username; or {@code null}. */
    public String getSubject() {
        return subject;
    }

    /** The {@code aud} of the JWT the signing key signs, or {@code null}. */
    public String getAssertionAudience() {
        return assertionAudience;
    }

    /** The refresh token for the refresh token grant, or {@code null}. */
    public String getRefreshToken() {
        return refreshToken;
    }

    /** Requested scopes in the order given, without duplicates; unmodifiable. */
    public List<String> getScopes() {
        return scopes;
    }

    /** Extra form fields for the token request; unmodifiable. */
    public Map<String, String> getTokenParameters() {
        return tokenParameters;
    }

    /** The caller's own data, never sent anywhere; unmodifiable. */
    public Map<String, String> getAttributes() {
        return attributes;
    }

    /** One attribute, or {@code null}. */
    public String getAttribute(String name) {
        return attributes.get(name);
    }

    ClientAuthentication clientAuthentication() {
        if (signingKey != null && grant != Grant.JWT_BEARER) {
            return ClientAuthentication.PRIVATE_KEY_JWT;
        }
        if (clientSecret != null) {
            return ClientAuthentication.CLIENT_SECRET;
        }
        if (clientCertificate != null) {
            return ClientAuthentication.MUTUAL_TLS;
        }
        return ClientAuthentication.NONE;
    }

    /** All settings except secrets and key material; secrets show as {@code ****}. */
    @Override
    public String toString() {
        return "ClientInfo{" + label(service, tenant, tenant == null)
                + ", grant=" + grant
                + ", tokenUrl=" + displayUrl(tokenUrl)
                + ", clientId=" + Strings.safe(clientId)
                + (clientSecret == null ? "" : ", clientSecret=****")
                + (signingKey == null ? "" : ", signingKey=" + signingKey)
                + (clientCertificate == null ? "" : ", clientCertificate=" + clientCertificate)
                + (subject == null ? "" : ", subject=" + Strings.safe(subject))
                + (assertionAudience == null ? "" : ", assertionAudience=" + Strings.safe(assertionAudience))
                + (refreshToken == null ? "" : ", refreshToken=****")
                + (scopes.isEmpty() ? "" : ", scopes=" + Strings.safe(scopes.toString()))
                + (tokenParameters.isEmpty() ? "" : ", tokenParameters=" + Strings.safe(tokenParameters.keySet().toString()))
                + (attributes.isEmpty() ? "" : ", attributes=" + Strings.safe(attributes.keySet().toString()))
                + '}';
    }

    /** {@code service/tenant} or {@code service (global)}. */
    private static String label(String service, String tenant, boolean global) {
        String s = service == null ? "?" : Strings.safe(service);
        return global ? s + " (global)" : s + "/" + (tenant == null ? "?" : Strings.safe(tenant));
    }

    /** Scheme, host, port and path: the query may carry values that don't belong in logs. */
    private static String displayUrl(String url) {
        try {
            URI u = new URI(url);
            return Strings.safe(u.getScheme() + "://" + u.getRawAuthority() + (u.getRawPath() == null ? "" : u.getRawPath()));
        } catch (URISyntaxException e) {
            return "(invalid)";
        }
    }

    /**
     * Why {@code url} can't be the token URL, or {@code null} if it can: it must parse, be absolute
     * https with a host, and have no user info, backslash (URL parsers disagree about it) or fragment.
     * A query is allowed (RFC 6749 section 3.2).
     */
    static String urlProblem(String url) {
        if (url == null) {
            return "is required";
        }
        if (url.indexOf('\\') >= 0) {
            return "must not contain a backslash";
        }
        URI uri;
        try {
            uri = new URI(url);
        } catch (URISyntaxException e) {
            return "is not a valid URL";
        }
        if (!uri.isAbsolute() || !"https".equalsIgnoreCase(uri.getScheme())) {
            return "must be an https URL";
        }
        try {
            uri.toURL();
        } catch (MalformedURLException | IllegalArgumentException e) {
            return "is not a valid URL";
        }
        if (uri.getRawUserInfo() != null) {
            return "must not contain user info";
        }
        if (uri.getHost() == null) {
            return "must have a host";
        }
        if (uri.getRawFragment() != null) {
            return "must not have a fragment";
        }
        return null;
    }

    /** Collects the settings; not thread-safe. {@link #build()} checks them all at once. */
    public static final class Builder {

        private final String service;
        private final String tenant;
        private final boolean global;
        private String tokenUrl;
        private Grant grant = Grant.CLIENT_CREDENTIALS;
        private String clientId;
        private String clientSecret;
        private ClientKey signingKey;
        private ClientKey clientCertificate;
        private String subject;
        private String assertionAudience;
        private String refreshToken;
        private final List<String> scopes = new ArrayList<String>();
        // a null key stands for a blank name, reported by build()
        private final Map<String, String> tokenParameters = new LinkedHashMap<String, String>();
        private final Map<String, String> attributes = new LinkedHashMap<String, String>();

        private Builder(String service, String tenant, boolean global) {
            this.service = Strings.trim(service);
            this.tenant = Strings.trim(tenant);
            this.global = global;
        }

        /** The token endpoint; must be https. */
        public Builder tokenUrl(String v) {
            tokenUrl = Strings.trim(v);
            return this;
        }

        /** Defaults to {@link Grant#CLIENT_CREDENTIALS}. */
        public Builder grant(Grant v) {
            grant = v;
            return this;
        }

        public Builder clientId(String v) {
            clientId = Strings.trim(v);
            return this;
        }

        public Builder clientSecret(String v) {
            clientSecret = Strings.trim(v);
            return this;
        }

        /**
         * The key that signs a JWT: with {@link Grant#JWT_BEARER} the grant's assertion; with the other
         * grants a {@code private_key_jwt} client assertion instead of a client secret (e.g. an Entra ID
         * certificate credential, with the certificate in the key, or an Okta key with its key ID).
         */
        public Builder signingKey(ClientKey v) {
            signingKey = v;
            return this;
        }

        /** Client certificate for mutual TLS to the token endpoint (RFC 8705); the key must have a certificate. */
        public Builder clientCertificate(ClientKey v) {
            clientCertificate = v;
            return this;
        }

        /** The JWT bearer assertion's {@code sub}, e.g. a DocuSign user ID or a Salesforce username. */
        public Builder subject(String v) {
            subject = Strings.trim(v);
            return this;
        }

        /**
         * The {@code aud} of the JWT the signing key signs: required for the JWT bearer grant (e.g.
         * {@code account-d.docusign.com}); for a {@code private_key_jwt} client assertion it defaults to the token URL.
         */
        public Builder assertionAudience(String v) {
            assertionAudience = Strings.trim(v);
            return this;
        }

        /** The refresh token for {@link Grant#REFRESH_TOKEN}. */
        public Builder refreshToken(String v) {
            refreshToken = Strings.trim(v);
            return this;
        }

        /** Adds scopes, one per argument (no spaces inside a scope); duplicates are dropped. */
        public Builder scope(String... v) {
            if (v == null) {
                scopes.add(null);
            } else {
                scopes.addAll(Arrays.asList(v));
            }
            return this;
        }

        /** An extra form field for the token request, e.g. {@code audience} or {@code resource}; set again to replace. */
        public Builder tokenParameter(String name, String value) {
            tokenParameters.put(Strings.trim(name), value);
            return this;
        }

        /** The caller's own data, kept with the client info and never sent; set again to replace. */
        public Builder attribute(String name, String value) {
            attributes.put(Strings.trim(name), value);
            return this;
        }

        /**
         * @throws IllegalArgumentException listing every problem found; the message never contains secrets
         */
        public ClientInfo build() {
            return build(Clock.systemUTC());
        }

        ClientInfo build(Clock clock) {
            List<String> problems = new ArrayList<String>();
            if (service == null) {
                problems.add("service is required");
            }
            if (!global && tenant == null) {
                problems.add("tenant is required (use ClientInfo.global(service) for all tenants)");
            }
            String urlProblem = urlProblem(tokenUrl);
            if (urlProblem != null) {
                problems.add("tokenUrl " + urlProblem);
            }
            if (clientId == null) {
                problems.add("clientId is required");
            }
            checkGrant(problems);
            checkCertificate("signingKey", signingKey, clock.instant(), problems);
            checkCertificate("clientCertificate", clientCertificate, clock.instant(), problems);
            List<String> scopeList = checkScopes(problems);
            Map<String, String> params = toMap("tokenParameter", tokenParameters, true, problems);
            Map<String, String> attrs = toMap("attribute", attributes, false, problems);
            if (!problems.isEmpty()) {
                throw new IllegalArgumentException("Invalid ClientInfo for " + label(service, tenant, global) + ": "
                        + String.join("; ", problems));
            }
            return new ClientInfo(this, scopeList, params, attrs);
        }

        private void checkGrant(List<String> problems) {
            if (grant == null) {
                problems.add("grant is required");
                return;
            }
            boolean jwtBearer = grant == Grant.JWT_BEARER;
            switch (grant) {
                case CLIENT_CREDENTIALS:
                    if (clientSecret == null && signingKey == null && clientCertificate == null) {
                        problems.add("CLIENT_CREDENTIALS needs a clientSecret, signingKey or clientCertificate");
                    }
                    break;
                case JWT_BEARER:
                    if (signingKey == null) {
                        problems.add("JWT_BEARER needs a signingKey");
                    }
                    if (assertionAudience == null) {
                        problems.add("JWT_BEARER needs an assertionAudience");
                    }
                    break;
                case REFRESH_TOKEN:
                    if (refreshToken == null) {
                        problems.add("REFRESH_TOKEN needs a refreshToken");
                    }
                    break;
                default:
                    throw new IllegalStateException("unhandled grant " + grant);
            }
            if (!jwtBearer && clientSecret != null && signingKey != null) {
                problems.add("set clientSecret or signingKey, not both: each authenticates the client");
            }
            if (!jwtBearer && subject != null) {
                problems.add("subject is only used with JWT_BEARER");
            }
            if (!jwtBearer && signingKey == null && assertionAudience != null) {
                problems.add("assertionAudience is only used with a signingKey");
            }
            if (grant != Grant.REFRESH_TOKEN && refreshToken != null) {
                problems.add("refreshToken is only used with REFRESH_TOKEN");
            }
            if (clientCertificate != null && !clientCertificate.hasCertificate()) {
                problems.add("clientCertificate needs a ClientKey with a certificate");
            }
        }

        private static void checkCertificate(String name, ClientKey key, Instant now, List<String> problems) {
            if (key == null || !key.hasCertificate()) {
                return;
            }
            X509Certificate leaf = key.getCertificateChain().get(0);
            if (leaf.getNotAfter().toInstant().isBefore(now)) {
                problems.add(name + " certificate " + Strings.safe(leaf.getSubjectX500Principal().getName())
                        + " expired on " + leaf.getNotAfter().toInstant());
            }
        }

        private List<String> checkScopes(List<String> problems) {
            Set<String> out = new LinkedHashSet<String>();
            for (String s : scopes) {
                String t = Strings.trim(s);
                if (t == null) {
                    problems.add("scope must not be blank");
                } else if (t.matches(".*\\s.*")) {
                    problems.add("scope '" + Strings.safe(t) + "' must not contain spaces; pass each scope separately");
                } else {
                    out.add(t);
                }
            }
            return Collections.unmodifiableList(new ArrayList<String>(out));
        }

        private static Map<String, String> toMap(String kind, Map<String, String> entries, boolean tokenParameter,
                                                 List<String> problems) {
            Map<String, String> out = new LinkedHashMap<String, String>();
            for (Map.Entry<String, String> e : entries.entrySet()) {
                String name = e.getKey();
                if (name == null) {
                    problems.add(kind + " name must not be blank");
                    continue;
                }
                if (tokenParameter && RESERVED_TOKEN_PARAMETERS.contains(name.toLowerCase(Locale.ROOT))) {
                    problems.add(kind + " '" + Strings.safe(name) + "' is set by the library"
                            + ("scope".equalsIgnoreCase(name) ? "; use scope(...)" : ""));
                    continue;
                }
                if (e.getValue() == null) {
                    problems.add(kind + " '" + Strings.safe(name) + "' needs a value");
                    continue;
                }
                out.put(name, e.getValue());
            }
            return Collections.unmodifiableMap(out);
        }
    }
}
