package io.primelogiclab.oauthclient;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * The parts of an authorization server's metadata (RFC 8414, OpenID Connect Discovery) the library uses:
 * where to ask for tokens and how the client may authenticate there. Immutable.
 */
final class ServerMetadata {

    private final String sourceUrl;
    private final String issuer;
    private final String tokenEndpoint;
    private final String mtlsTokenEndpoint;
    private final List<String> tokenEndpointAuthMethods;

    private ServerMetadata(String sourceUrl, String issuer, String tokenEndpoint, String mtlsTokenEndpoint,
                           List<String> tokenEndpointAuthMethods) {
        this.sourceUrl = sourceUrl;
        this.issuer = issuer;
        this.tokenEndpoint = tokenEndpoint;
        this.mtlsTokenEndpoint = mtlsTokenEndpoint;
        this.tokenEndpointAuthMethods = tokenEndpointAuthMethods;
    }

    /** The fields of a parsed metadata document; values of the wrong type count as absent. */
    static ServerMetadata from(String sourceUrl, Map<String, Object> document) {
        Object aliases = document.get("mtls_endpoint_aliases");
        String mtls = aliases instanceof Map ? string(((Map<?, ?>) aliases).get("token_endpoint")) : null;
        List<String> methods = new ArrayList<String>();
        Object listed = document.get("token_endpoint_auth_methods_supported");
        if (listed instanceof List) {
            for (Object m : (List<?>) listed) {
                if (m instanceof String) {
                    methods.add((String) m);
                }
            }
        }
        return new ServerMetadata(sourceUrl, string(document.get("issuer")), string(document.get("token_endpoint")),
                mtls, Collections.unmodifiableList(methods));
    }

    /** Where the document was read. */
    String sourceUrl() {
        return sourceUrl;
    }

    /** The issuer it declares, or {@code null}. */
    String issuer() {
        return issuer;
    }

    /** {@code token_endpoint}, or {@code null}. */
    String tokenEndpoint() {
        return tokenEndpoint;
    }

    /** {@code mtls_endpoint_aliases.token_endpoint} (RFC 8705), for clients with a certificate; or {@code null}. */
    String mtlsTokenEndpoint() {
        return mtlsTokenEndpoint;
    }

    /** {@code token_endpoint_auth_methods_supported}; empty when the server doesn't say. */
    List<String> tokenEndpointAuthMethods() {
        return tokenEndpointAuthMethods;
    }

    private static String string(Object o) {
        return o instanceof String ? (String) o : null;
    }
}
