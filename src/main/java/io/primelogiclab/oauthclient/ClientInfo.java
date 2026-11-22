package io.primelogiclab.oauthclient;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
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
 *         .assertionClaim("scope", "signature impersonation")  // DocuSign wants scopes in the assertion
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
 * {@link #getClientSecret() client secret} (in an HTTP Basic header, or in the body when {@link
 * #isClientSecretInBody() asked}), else a {@link #getClientCertificate() client certificate} alone
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
        /** Client ID and secret in an HTTP Basic header ({@code client_secret_basic}, RFC 6749 section 2.3.1). */
        CLIENT_SECRET_BASIC,
        /** {@code client_id} and {@code client_secret} in the request body ({@code client_secret_post}). */
        CLIENT_SECRET_POST,
        /** A JWT client assertion signed with the signing key (RFC 7523 section 2.2). */
        PRIVATE_KEY_JWT,
        /** The client certificate in the TLS handshake (RFC 8705), with {@code client_id} in the body. */
        MUTUAL_TLS
    }

    /** Form fields the library sets itself; a token parameter may not override them. */
    static final Set<String> RESERVED_TOKEN_PARAMETERS = Collections.unmodifiableSet(new HashSet<String>(Arrays.asList(
            "grant_type", "client_id", "client_secret", "client_assertion", "client_assertion_type",
            "assertion", "refresh_token", "scope")));

    /** The longest pause between token requests after failures, unless {@link Builder#maxTokenRetryDelay(Duration)} says otherwise. */
    static final Duration DEFAULT_MAX_TOKEN_RETRY_DELAY = Duration.ofMinutes(5);
    /** The most {@link Builder#maxTokenRetryDelay(Duration)} accepts. */
    static final Duration MAX_TOKEN_RETRY_DELAY_LIMIT = Duration.ofHours(24);

    /** JWT claims the library sets itself; an assertion claim may not override them. */
    static final Set<String> RESERVED_ASSERTION_CLAIMS = Collections.unmodifiableSet(new HashSet<String>(Arrays.asList(
            "iss", "sub", "aud", "exp", "iat", "nbf", "jti")));

    private final String service;
    private final String tenant;
    private final String tokenUrl;
    private final String issuer;
    private final String metadataUrl;
    private final Grant grant;
    private final String clientId;
    private final String clientSecret;
    private final boolean clientSecretInBody;
    private final ClientKey signingKey;
    private final ClientKey clientCertificate;
    private final String subject;
    private final String assertionAudience;
    private final Map<String, String> assertionClaims;
    private final String refreshToken;
    private final List<String> scopes;
    private final Map<String, String> tokenParameters;
    private final String introspectionUrl;
    private final Map<String, String> attributes;
    private final List<String> allowedHosts;
    private final Duration maxTokenRetryDelay;
    /** SHA-256 of the credentials, made on first use; never shown. */
    private volatile String credentialsFingerprint;

    private ClientInfo(Builder b, List<String> scopes, Map<String, String> assertionClaims,
                       Map<String, String> tokenParameters, Map<String, String> attributes, List<String> allowedHosts) {
        this.service = b.service;
        this.tenant = b.global ? null : b.tenant;
        this.tokenUrl = b.tokenUrl;
        this.issuer = b.issuer;
        this.metadataUrl = b.metadataUrl;
        this.grant = b.grant;
        this.clientId = b.clientId;
        this.clientSecret = b.clientSecret;
        this.clientSecretInBody = b.clientSecretInBody;
        this.signingKey = b.signingKey;
        this.clientCertificate = b.clientCertificate;
        this.subject = b.subject;
        this.assertionAudience = b.assertionAudience;
        this.assertionClaims = assertionClaims;
        this.refreshToken = b.refreshToken;
        this.scopes = scopes;
        this.tokenParameters = tokenParameters;
        this.introspectionUrl = b.introspectionUrl;
        this.attributes = attributes;
        this.allowedHosts = allowedHosts;
        this.maxTokenRetryDelay = b.maxTokenRetryDelay;
    }

    /**
     * Client info for one tenant of a service, e.g. a DocuSign account per customer.
     *
     * @param service the service type as the caller names it, e.g. {@code docusign}
     * @param tenant  the tenant code; tokens are cached per service and tenant
     * @return a builder; {@link Builder#build()} checks both are set
     */
    public static Builder forTenant(String service, String tenant) {
        return new Builder(service, tenant, false);
    }

    /**
     * Client info shared by all tenants of a service, e.g. one Salesforce integration for everyone.
     *
     * @param service the service type as the caller names it, e.g. {@code salesforce}
     * @return a builder; {@link Builder#build()} checks the service is set
     */
    public static Builder global(String service) {
        return new Builder(service, null, true);
    }

    /**
     * The service type.
     *
     * @return the service type as the caller named it, e.g. {@code docusign}
     */
    public String getService() {
        return service;
    }

    /**
     * The tenant.
     *
     * @return the tenant code, or {@code null} when {@link #isGlobal() global}
     */
    public String getTenant() {
        return tenant;
    }

    /**
     * Whether this client info is shared by all tenants.
     *
     * @return true when built with {@link #global(String)}
     */
    public boolean isGlobal() {
        return tenant == null;
    }

    /**
     * The token endpoint, when it is set directly.
     *
     * @return the https URL tokens are asked for at; {@code null} when it comes from the server's metadata
     *         ({@link #getIssuer()}, {@link #getMetadataUrl()})
     */
    public String getTokenUrl() {
        return tokenUrl;
    }

    /**
     * The token server's issuer, whose metadata (RFC 8414, OpenID Connect discovery) gives the token endpoint.
     *
     * @return the issuer URL, or {@code null} when it isn't set
     */
    public String getIssuer() {
        return issuer;
    }

    /**
     * The token server's metadata document, read for the token endpoint instead of the issuer's well-known locations.
     *
     * @return the document's https URL, or {@code null} when it isn't set
     */
    public String getMetadataUrl() {
        return metadataUrl;
    }

    /**
     * The grant.
     *
     * @return how tokens are asked for; {@link Grant#CLIENT_CREDENTIALS} unless set
     */
    public Grant getGrant() {
        return grant;
    }

    /**
     * The client ID.
     *
     * @return the client ID the token server knows this client by
     */
    public String getClientId() {
        return clientId;
    }

    /**
     * The client secret. Keep it out of logs; {@link #toString()} never shows it.
     *
     * @return the secret, or {@code null} when none is set
     */
    public String getClientSecret() {
        return clientSecret;
    }

    /**
     * Where the client secret goes.
     *
     * @return true when it goes in the request body instead of an HTTP Basic header
     */
    public boolean isClientSecretInBody() {
        return clientSecretInBody;
    }

    /**
     * The signing key.
     *
     * @return the key that signs the JWT bearer grant's assertion, or the {@code private_key_jwt} client
     *         assertion with other grants; or {@code null} when none is set
     */
    public ClientKey getSigningKey() {
        return signingKey;
    }

    /**
     * The client certificate.
     *
     * @return the key and certificate presented in mutual TLS, or {@code null} when none is set
     */
    public ClientKey getClientCertificate() {
        return clientCertificate;
    }

    /**
     * The user the token acts for.
     *
     * @return the JWT bearer assertion's {@code sub} (e.g. a DocuSign user ID or Salesforce username), or the
     *         user a refresh token belongs to; or {@code null} when none is set
     */
    public String getSubject() {
        return subject;
    }

    /**
     * The audience of the JWT the signing key signs.
     *
     * @return the {@code aud} value, or {@code null} when none is set
     */
    public String getAssertionAudience() {
        return assertionAudience;
    }

    /**
     * The extra claims of the JWT the signing key signs.
     *
     * @return the claims by name, e.g. DocuSign's {@code scope}, in the order set; unmodifiable
     */
    public Map<String, String> getAssertionClaims() {
        return assertionClaims;
    }

    /**
     * The refresh token. Keep it out of logs; {@link #toString()} never shows it.
     *
     * @return the refresh token for {@link Grant#REFRESH_TOKEN}, or {@code null} when none is set
     */
    public String getRefreshToken() {
        return refreshToken;
    }

    /**
     * The default scopes. Scopes the app passes for a request replace them for that request.
     *
     * @return the scopes in the order given, without duplicates; unmodifiable
     */
    public List<String> getScopes() {
        return scopes;
    }

    /**
     * The scopes for one token: {@code requested} when the app passed any, checked like {@link
     * Builder#scope(String...)} (not blank, no spaces, duplicates dropped, order kept); else {@link #getScopes()}.
     *
     * @throws IllegalArgumentException if a requested scope is blank or contains spaces
     */
    List<String> effectiveScopes(List<String> requested) {
        if (requested == null || requested.isEmpty()) {
            return scopes;
        }
        List<String> problems = new ArrayList<String>();
        List<String> out = checkScopes(requested, problems);
        if (!problems.isEmpty()) {
            throw new IllegalArgumentException("Invalid scopes for " + label() + ": " + String.join("; ", problems));
        }
        return out;
    }

    /**
     * The extra form fields for the token request.
     *
     * @return the fields by name, in the order set; unmodifiable
     */
    public Map<String, String> getTokenParameters() {
        return tokenParameters;
    }

    /**
     * The token introspection endpoint (RFC 7662), to be asked for the expiry of a token that doesn't carry
     * one; or {@code null}. Package-private until introspection is built: nothing asks it yet.
     */
    String getIntrospectionUrl() {
        return introspectionUrl;
    }

    /**
     * The longest the library waits after failed token requests before it asks again. After a failure it
     * waits 5 seconds, doubled with each further failure in a row, up to this.
     *
     * @return the ceiling, 5 minutes unless set; zero when the wait is turned off
     */
    public Duration getMaxTokenRetryDelay() {
        return maxTokenRetryDelay;
    }

    /**
     * The caller's own data, never sent anywhere.
     *
     * @return the attributes by name, in the order set; unmodifiable
     */
    public Map<String, String> getAttributes() {
        return attributes;
    }

    /**
     * One attribute.
     *
     * @param name the attribute's name
     * @return its value, or {@code null} when it isn't set
     */
    public String getAttribute(String name) {
        return attributes.get(name);
    }

    /**
     * The hosts calls with this client info's token or client certificate may go to.
     *
     * @return the entries, lowercase, in the order given; empty when any https host is allowed. Unmodifiable
     */
    public List<String> getAllowedHosts() {
        return allowedHosts;
    }

    /**
     * Whether a call to a host may carry this client info's token or client certificate.
     *
     * @param host a host name, e.g. {@code acme.my.salesforce.com}; case doesn't matter, and a trailing dot
     *             is ignored
     * @return true when there is no allowed-host list, or the host is on it, exactly or below a {@code *.}
     *         entry; false for {@code null} or anything that isn't a host name
     */
    public boolean allowsHost(String host) {
        if (host == null) {
            return false;
        }
        String h = normalizeHost(host);
        if (h.indexOf('*') >= 0 || hostProblem(h) != null) {
            return false; // not a host name, e.g. "evil.com/.example.com"
        }
        if (allowedHosts.isEmpty()) {
            return true;
        }
        for (String allowed : allowedHosts) {
            if (allowed.startsWith("*.")) {
                String suffix = allowed.substring(1); // ".example.com"
                if (h.endsWith(suffix) && h.length() > suffix.length()) {
                    return true;
                }
            } else if (allowed.equals(h)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Why {@code h} (lowercase, no trailing dot) can't be a host, or an allowed-host entry with a leading
     * {@code *.}; {@code null} if it can.
     */
    static String hostProblem(String h) {
        if (h.startsWith("[") && h.endsWith("]")) {
            return h.length() > 2 && h.substring(1, h.length() - 1).matches("[0-9a-f:.]+")
                    ? null : "is not a valid IPv6 address";
        }
        if (h.contains("://") || h.contains("/") || h.contains("@") || h.contains(":")) {
            return "must be a host name only: no scheme, path, user info or port";
        }
        String name = h;
        if (h.contains("*")) {
            if (!h.startsWith("*.") || h.indexOf('*', 1) >= 0) {
                return "may only use * as its first label, as in *.example.com";
            }
            name = h.substring(2);
            if (name.indexOf('.') < 0) {
                return "is too broad: a wildcard needs a domain of at least two labels, as in *.example.com";
            }
            if (name.substring(name.lastIndexOf('.') + 1).matches("[0-9]+")) {
                return "can't be a wildcard over an IP address";
            }
        }
        for (String label : name.split("\\.", -1)) {
            if (!label.matches("[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?")) {
                return "is not a valid host name";
            }
        }
        return null;
    }

    private static String normalizeHost(String host) {
        String h = host.trim().toLowerCase(Locale.ROOT);
        return h.endsWith(".") ? h.substring(0, h.length() - 1) : h;
    }

    /**
     * The settings that decide what a token grants: a cached token obtained with other values isn't
     * reused. Credentials are left out, so a rotated secret, key or refresh token keeps the cached token;
     * the client certificate is in, since a token may be bound to it (RFC 8705).
     */
    List<Object> tokenSettings() {
        // allowedHosts too: a client info without the list mustn't reuse a token another keeps to some hosts
        return Collections.unmodifiableList(Arrays.<Object>asList(allowedHosts, tokenUrl, issuer, metadataUrl, grant,
                clientId, subject, assertionAudience, assertionClaims, scopes, tokenParameters,
                clientCertificate == null ? null : clientCertificate.getCertificateChain().get(0)));
    }

    /**
     * A SHA-256 fingerprint of the credentials (secret, refresh token, signing key, client certificate), so a
     * failed token request is held only against the same ones: a fixed secret or a new key is tried at once.
     * Equal for equal values, also across rebuilds from the same configuration. Never shown or logged.
     */
    String credentialsFingerprint() {
        String f = credentialsFingerprint;
        if (f == null) {
            f = fingerprint();
            credentialsFingerprint = f;
        }
        return f;
    }

    private String fingerprint() {
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e); // every Java platform has SHA-256
        }
        part(digest, clientSecret == null ? null : clientSecret.getBytes(StandardCharsets.UTF_8));
        part(digest, refreshToken == null ? null : refreshToken.getBytes(StandardCharsets.UTF_8));
        keyParts(digest, signingKey);
        keyParts(digest, clientCertificate);
        return Base64.getEncoder().encodeToString(digest.digest());
    }

    private static void keyParts(MessageDigest digest, ClientKey key) {
        if (key == null) {
            part(digest, null);
            return;
        }
        PrivateKey privateKey = key.getPrivateKey();
        byte[] encoded = privateKey.getEncoded();
        // a key that can't be exported (a hardware token) counts by its object
        part(digest, encoded != null ? encoded
                : ("object:" + System.identityHashCode(privateKey)).getBytes(StandardCharsets.UTF_8));
        part(digest, key.getKeyId() == null ? null : key.getKeyId().getBytes(StandardCharsets.UTF_8));
        try {
            part(digest, key.hasCertificate() ? key.getCertificateChain().get(0).getEncoded() : null);
        } catch (CertificateEncodingException e) {
            part(digest, ("unencodable:" + System.identityHashCode(key)).getBytes(StandardCharsets.UTF_8));
        }
    }

    /** One part, marked and length-prefixed, so two different sets of values never hash the same input. */
    private static void part(MessageDigest digest, byte[] bytes) {
        if (bytes == null) {
            digest.update((byte) 0);
            return;
        }
        digest.update((byte) 1);
        int n = bytes.length;
        digest.update(new byte[] {(byte) (n >>> 24), (byte) (n >>> 16), (byte) (n >>> 8), (byte) n});
        digest.update(bytes);
    }

    /**
     * The user a cached token belongs to, part of the cache key: the subject with the JWT bearer and refresh
     * token grants; {@code null} with client credentials, whose token serves the whole tenant.
     */
    String cacheUser() {
        return grant == Grant.CLIENT_CREDENTIALS ? null : subject;
    }

    ClientAuthentication clientAuthentication() {
        if (signingKey != null && grant != Grant.JWT_BEARER) {
            return ClientAuthentication.PRIVATE_KEY_JWT;
        }
        if (clientSecret != null) {
            return clientSecretInBody ? ClientAuthentication.CLIENT_SECRET_POST : ClientAuthentication.CLIENT_SECRET_BASIC;
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
                + (tokenUrl == null ? "" : ", tokenUrl=" + displayUrl(tokenUrl))
                + (issuer == null ? "" : ", issuer=" + displayUrl(issuer))
                + (metadataUrl == null ? "" : ", metadataUrl=" + displayUrl(metadataUrl))
                + ", clientId=" + Strings.safe(clientId)
                + (clientSecret == null ? "" : ", clientSecret=****" + (clientSecretInBody ? " (in body)" : ""))
                + (signingKey == null ? "" : ", signingKey=" + signingKey)
                + (clientCertificate == null ? "" : ", clientCertificate=" + clientCertificate)
                + (subject == null ? "" : ", subject=" + Strings.safe(subject))
                + (assertionAudience == null ? "" : ", assertionAudience=" + Strings.safe(assertionAudience))
                + (assertionClaims.isEmpty() ? "" : ", assertionClaims=" + Strings.safe(assertionClaims.keySet().toString()))
                + (refreshToken == null ? "" : ", refreshToken=****")
                + (scopes.isEmpty() ? "" : ", scopes=" + Strings.safe(scopes.toString()))
                + (tokenParameters.isEmpty() ? "" : ", tokenParameters=" + Strings.safe(tokenParameters.keySet().toString()))
                + (introspectionUrl == null ? "" : ", introspectionUrl=" + displayUrl(introspectionUrl))
                + (attributes.isEmpty() ? "" : ", attributes=" + Strings.safe(attributes.keySet().toString()))
                + (allowedHosts.isEmpty() ? "" : ", allowedHosts=" + Strings.safe(allowedHosts.toString()))
                + (maxTokenRetryDelay.equals(DEFAULT_MAX_TOKEN_RETRY_DELAY) ? "" : ", maxTokenRetryDelay=" + maxTokenRetryDelay)
                + '}';
    }

    /** {@code service/tenant} or {@code service (global)}, safe for logs and messages. */
    String label() {
        return label(service, tenant, tenant == null);
    }

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

    /** Trimmed scopes without duplicates, in the order given; a blank one or one with spaces goes to {@code problems}. */
    static List<String> checkScopes(List<String> scopes, List<String> problems) {
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

    /**
     * Why {@code url} can't be the token or introspection URL, or {@code null} if it can: it must parse, be absolute
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
        private String issuer;
        private String metadataUrl;
        private Grant grant = Grant.CLIENT_CREDENTIALS;
        private String clientId;
        private String clientSecret;
        private boolean clientSecretInBody;
        private ClientKey signingKey;
        private ClientKey clientCertificate;
        private String subject;
        private String assertionAudience;
        private String refreshToken;
        private final List<String> scopes = new ArrayList<String>();
        // a null key stands for a blank name, reported by build()
        private final Map<String, String> assertionClaims = new LinkedHashMap<String, String>();
        private final Map<String, String> tokenParameters = new LinkedHashMap<String, String>();
        private String introspectionUrl;
        private final Map<String, String> attributes = new LinkedHashMap<String, String>();
        private final List<String> allowedHosts = new ArrayList<String>();
        private Duration maxTokenRetryDelay = DEFAULT_MAX_TOKEN_RETRY_DELAY;

        private Builder(String service, String tenant, boolean global) {
            this.service = Strings.trim(service);
            this.tenant = Strings.trim(tenant);
            this.global = global;
        }

        /**
         * The token endpoint. Required, unless the server's metadata gives it: then set {@link #issuer(String)}
         * or {@link #metadataUrl(String)} instead.
         *
         * @param tokenUrl an https URL without user info
         * @return this builder
         */
        public Builder tokenUrl(String tokenUrl) {
            this.tokenUrl = Strings.trim(tokenUrl);
            return this;
        }

        /**
         * The token server's issuer, instead of a {@link #tokenUrl(String) token URL}: the token endpoint comes from
         * its metadata, read from {@code /.well-known/openid-configuration} or RFC 8414's {@code
         * /.well-known/oauth-authorization-server} and kept for a day. The document must name this exact issuer.
         * With a {@link #clientCertificate(ClientKey) client certificate}, its mutual TLS token endpoint is used
         * when it lists one; when it lists the client authentication methods and leaves out the one the secret
         * would use, the other (Basic header or form body) is used if listed.
         *
         * @param issuer the issuer, an https URL without user info, query or fragment, e.g.
         *               {@code https://login.microsoftonline.com/{tenant}/v2.0}
         * @return this builder
         */
        public Builder issuer(String issuer) {
            this.issuer = Strings.trim(issuer);
            return this;
        }

        /**
         * The token server's metadata document, when it isn't at the issuer's well-known locations; read like
         * the {@link #issuer(String) issuer}'s, which it must name when that is set too.
         *
         * @param metadataUrl an https URL without user info
         * @return this builder
         */
        public Builder metadataUrl(String metadataUrl) {
            this.metadataUrl = Strings.trim(metadataUrl);
            return this;
        }

        /**
         * How tokens are asked for.
         *
         * @param grant the grant; {@link Grant#CLIENT_CREDENTIALS} unless set
         * @return this builder
         */
        public Builder grant(Grant grant) {
            this.grant = grant;
            return this;
        }

        /**
         * The client ID. Required: it is also the issuer of the JWTs the signing key signs.
         *
         * @param clientId the ID the token server knows this client by
         * @return this builder
         */
        public Builder clientId(String clientId) {
            this.clientId = Strings.trim(clientId);
            return this;
        }

        /**
         * The client secret, sent in an HTTP Basic header unless {@link #clientSecretInBody(boolean)} says
         * otherwise. Not together with a {@link #signingKey(ClientKey) signing key}, except with the JWT
         * bearer grant.
         *
         * @param clientSecret the secret
         * @return this builder
         */
        public Builder clientSecret(String clientSecret) {
            this.clientSecret = Strings.trim(clientSecret);
            return this;
        }

        /**
         * Where the client secret goes.
         *
         * @param clientSecretInBody true to send {@code client_id} and {@code client_secret} as form fields
         *                           ({@code client_secret_post}, e.g. Atlassian) instead of the default HTTP
         *                           Basic header ({@code client_secret_basic}, the method every OAuth 2.0
         *                           server must support)
         * @return this builder
         */
        public Builder clientSecretInBody(boolean clientSecretInBody) {
            this.clientSecretInBody = clientSecretInBody;
            return this;
        }

        /**
         * The key that signs a JWT: with {@link Grant#JWT_BEARER} the grant's assertion; with the other
         * grants a {@code private_key_jwt} client assertion instead of a client secret (e.g. an Entra ID
         * certificate credential, with the certificate in the key, or an Okta key with its key ID).
         *
         * @param signingKey the key
         * @return this builder
         */
        public Builder signingKey(ClientKey signingKey) {
            this.signingKey = signingKey;
            return this;
        }

        /**
         * The client certificate for mutual TLS (RFC 8705), presented to the token endpoint and on calls with
         * this client info's token, for certificate-bound tokens. Alone it authenticates the client.
         *
         * @param clientCertificate a key with its certificate
         * @return this builder
         */
        public Builder clientCertificate(ClientKey clientCertificate) {
            this.clientCertificate = clientCertificate;
            return this;
        }

        /**
         * The user the token acts for: with {@link Grant#JWT_BEARER} the assertion's {@code sub} (a DocuSign
         * user ID, a Salesforce username); with {@link Grant#REFRESH_TOKEN} the user the refresh token
         * belongs to, which is required there and never sent. Tokens are cached per user, so one user never
         * gets another's token; client credentials tokens are shared by the whole tenant.
         *
         * @param subject the user, as the token server knows them
         * @return this builder
         */
        public Builder subject(String subject) {
            this.subject = Strings.trim(subject);
            return this;
        }

        /**
         * The {@code aud} of the JWT the signing key signs: required for the JWT bearer grant (for example
         * {@code account-d.docusign.com}); for a {@code private_key_jwt} client assertion it defaults to the token URL.
         *
         * @param assertionAudience the {@code aud} value
         * @return this builder
         */
        public Builder assertionAudience(String assertionAudience) {
            this.assertionAudience = Strings.trim(assertionAudience);
            return this;
        }

        /**
         * An extra claim for the JWT the signing key signs, as a string; set again to replace. For services
         * that want more than the standard claims, e.g. DocuSign's {@code scope} ({@code "signature
         * impersonation"}). The library sets {@code iss}, {@code sub}, {@code aud}, {@code exp}, {@code iat},
         * {@code nbf} and {@code jti} itself.
         *
         * @param name  the claim's name; not one the library sets
         * @param value the claim's value
         * @return this builder
         */
        public Builder assertionClaim(String name, String value) {
            assertionClaims.put(Strings.trim(name), value);
            return this;
        }

        /**
         * The refresh token for {@link Grant#REFRESH_TOKEN}, which also needs the {@link #subject(String)
         * user} it belongs to.
         *
         * @param refreshToken the refresh token
         * @return this builder
         */
        public Builder refreshToken(String refreshToken) {
            this.refreshToken = Strings.trim(refreshToken);
            return this;
        }

        /**
         * Adds default scopes, one per argument (no spaces inside a scope); duplicates are dropped. Sent as
         * the {@code scope} form field with every grant, unless the app passes its own scopes for a request,
         * which then replace these; leave them out when only the app knows them. A service that wants scopes
         * inside the JWT bearer assertion instead (DocuSign) takes {@link #assertionClaim(String, String)
         * assertionClaim("scope", ...)}.
         *
         * @param scopes one or more scopes
         * @return this builder
         */
        public Builder scope(String... scopes) {
            if (scopes == null) {
                this.scopes.add(null);
            } else {
                this.scopes.addAll(Arrays.asList(scopes));
            }
            return this;
        }

        /**
         * An extra form field for the token request, such as {@code audience} or {@code resource}; set again to
         * replace.
         *
         * @param name  the field's name; not one the library sets ({@code grant_type}, {@code client_id},
         *              {@code client_secret}, {@code client_assertion}, {@code client_assertion_type},
         *              {@code assertion}, {@code refresh_token}, {@code scope})
         * @param value the field's value
         * @return this builder
         */
        public Builder tokenParameter(String name, String value) {
            tokenParameters.put(Strings.trim(name), value);
            return this;
        }

        /**
         * The token introspection endpoint (RFC 7662), e.g. Salesforce's {@code /services/oauth2/introspect};
         * must be https. Meant to be asked once per new token that says nothing about its expiry (no JWT
         * {@code exp}, no {@code expires_in}). Package-private until introspection is built: until then such
         * a token is kept until the service answers 401.
         */
        Builder introspectionUrl(String v) {
            introspectionUrl = Strings.trim(v);
            return this;
        }

        /**
         * Hosts that calls carrying this client info's token or client certificate may go to, one per
         * argument; set again to add more. An exact host ({@code api.example.com}), or {@code *.} and a
         * domain for any host below it ({@code *.my.salesforce.com}, not {@code my.salesforce.com} itself).
         * Without any, every https host is allowed. Recommended whenever a URL can come from a response,
         * such as Salesforce's {@code instance_url}.
         *
         * @param hosts one or more host names or {@code *.} entries, without scheme, port or path
         * @return this builder
         */
        public Builder allowedHost(String... hosts) {
            if (hosts == null) {
                allowedHosts.add(null);
            } else {
                allowedHosts.addAll(Arrays.asList(hosts));
            }
            return this;
        }

        /**
         * The longest the library waits between token requests after failures. After a failed token request
         * it sends no other for the same service, tenant, user and scopes for 5 seconds, doubled with each
         * further failure in a row, up to this; a token server's {@code Retry-After} (429, 503) counts too, up
         * to this. Calls meanwhile get the cached token while it hasn't expired, else fail at once with the
         * last failure. Changed credentials or token settings are tried at once. Raise it for a service that
         * caps token requests (Vertex: 10 per 8 hours).
         *
         * @param maxTokenRetryDelay 0 (no waiting) to 24 hours; 5 minutes unless set
         * @return this builder
         */
        public Builder maxTokenRetryDelay(Duration maxTokenRetryDelay) {
            this.maxTokenRetryDelay = maxTokenRetryDelay;
            return this;
        }

        /**
         * The caller's own data, kept with the client info and never sent; set again to replace.
         *
         * @param name  the attribute's name
         * @param value its value
         * @return this builder
         */
        public Builder attribute(String name, String value) {
            attributes.put(Strings.trim(name), value);
            return this;
        }

        /**
         * Checks every setting and builds the client info.
         *
         * @return the client info, immutable
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
            checkEndpoint(problems);
            if (clientId == null) {
                problems.add("clientId is required");
            }
            checkGrant(problems);
            checkCertificate("signingKey", signingKey, clock.instant(), problems);
            checkCertificate("clientCertificate", clientCertificate, clock.instant(), problems);
            if (signingKey != null) {
                String keyProblem = Jws.signingKeyProblem(signingKey.getPrivateKey());
                if (keyProblem != null) {
                    problems.add("signingKey can't sign: " + keyProblem);
                }
            }
            List<String> scopeList = checkScopes(scopes, problems);
            if (introspectionUrl != null) {
                String introspectionProblem = urlProblem(introspectionUrl);
                if (introspectionProblem != null) {
                    problems.add("introspectionUrl " + introspectionProblem);
                }
            }
            Map<String, String> claims = toMap("assertionClaim", assertionClaims, RESERVED_ASSERTION_CLAIMS, problems);
            Map<String, String> params = toMap("tokenParameter", tokenParameters, RESERVED_TOKEN_PARAMETERS, problems);
            Map<String, String> attrs = toMap("attribute", attributes, Collections.<String>emptySet(), problems);
            List<String> hosts = checkAllowedHosts(allowedHosts, problems);
            if (maxTokenRetryDelay == null || maxTokenRetryDelay.isNegative()
                    || maxTokenRetryDelay.compareTo(MAX_TOKEN_RETRY_DELAY_LIMIT) > 0) {
                problems.add("maxTokenRetryDelay must be 0 to 24 hours");
            }
            if (!problems.isEmpty()) {
                throw new IllegalArgumentException("Invalid ClientInfo for " + label(service, tenant, global) + ": "
                        + String.join("; ", problems));
            }
            return new ClientInfo(this, scopeList, claims, params, attrs, hosts);
        }

        /** A token URL, or an issuer and/or a metadata URL to read it from; every one an https URL. */
        private void checkEndpoint(List<String> problems) {
            boolean discovery = issuer != null || metadataUrl != null;
            if (tokenUrl != null && discovery) {
                problems.add("set tokenUrl, or issuer and/or metadataUrl to read it from the server's metadata, not both");
            }
            if (tokenUrl != null || !discovery) {
                String problem = urlProblem(tokenUrl);
                if (problem != null) {
                    problems.add("tokenUrl " + problem + (tokenUrl == null
                            ? " (or issuer or metadataUrl, to read it from the server's metadata)" : ""));
                }
            }
            if (issuer != null) {
                String problem = urlProblem(issuer);
                if (problem == null && URI.create(issuer).getRawQuery() != null) {
                    problem = "must not have a query"; // RFC 8414 section 2
                }
                if (problem != null) {
                    problems.add("issuer " + problem);
                }
            }
            if (metadataUrl != null) {
                String problem = urlProblem(metadataUrl);
                if (problem != null) {
                    problems.add("metadataUrl " + problem);
                }
            }
        }

        /** Lowercase hosts without duplicates, in the order given; a malformed one goes to {@code problems}. */
        private static List<String> checkAllowedHosts(List<String> hosts, List<String> problems) {
            Set<String> out = new LinkedHashSet<String>();
            int n = 0;
            for (String raw : hosts) {
                n++;
                if (Strings.isBlank(raw)) {
                    problems.add("allowedHost must not be blank");
                    continue;
                }
                String h = normalizeHost(raw);
                String problem = hostProblem(h);
                if (problem != null) {
                    problems.add("allowedHost " + describeEntry(raw.trim(), n) + " " + problem);
                } else {
                    out.add(h);
                }
            }
            return Collections.unmodifiableList(new ArrayList<String>(out));
        }

        /**
         * The entry for a message: shown when it looks like a host, else only its position, since a pasted URL
         * may carry user info or a key in its query.
         */
        private static String describeEntry(String raw, int position) {
            return raw.matches("[A-Za-z0-9.*\\[\\]: -]{1,253}") ? "'" + raw + "'" : "#" + position + " (not shown)";
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
                    if (subject == null) {
                        // a refresh token belongs to one user: without the user in the cache key, another
                        // user of the same service and tenant would get this user's token
                        problems.add("REFRESH_TOKEN needs a subject: the user the refresh token belongs to");
                    }
                    break;
                default:
                    throw new IllegalStateException("unhandled grant " + grant);
            }
            if (!jwtBearer && clientSecret != null && signingKey != null) {
                problems.add("set clientSecret or signingKey, not both: each authenticates the client");
            }
            if (grant == Grant.CLIENT_CREDENTIALS && subject != null) {
                problems.add("subject is only used with JWT_BEARER and REFRESH_TOKEN");
            }
            if (!jwtBearer && signingKey == null && assertionAudience != null) {
                problems.add("assertionAudience is only used with a signingKey");
            }
            if (signingKey == null && !assertionClaims.isEmpty()) {
                problems.add("assertionClaim is only used with a signingKey");
            }
            if (clientSecretInBody && clientSecret == null) {
                problems.add("clientSecretInBody is only used with a clientSecret");
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

        private static Map<String, String> toMap(String kind, Map<String, String> entries, Set<String> reserved,
                                                 List<String> problems) {
            Map<String, String> out = new LinkedHashMap<String, String>();
            for (Map.Entry<String, String> e : entries.entrySet()) {
                String name = e.getKey();
                if (name == null) {
                    problems.add(kind + " name must not be blank");
                    continue;
                }
                String lower = name.toLowerCase(Locale.ROOT);
                if (reserved.contains(lower)) {
                    problems.add(kind + " '" + Strings.safe(name) + "' is set by the library" + useInstead(lower));
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

        /** Points at the builder method for a reserved name that has one. */
        private static String useInstead(String reservedName) {
            if ("scope".equals(reservedName)) {
                return "; use scope(...)";
            }
            if ("sub".equals(reservedName)) {
                return "; use subject(...)";
            }
            if ("aud".equals(reservedName)) {
                return "; use assertionAudience(...)";
            }
            return "";
        }
    }
}
