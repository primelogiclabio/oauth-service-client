package io.primelogiclab.oauthclient;

/** OAuth 2.0 grant the library uses to get a token for a service. */
public enum Grant {

    /** RFC 6749 section 4.4: the client gets a token for itself (secret, signing key or client certificate). */
    CLIENT_CREDENTIALS("client_credentials"),
    /** RFC 7523: a JWT signed with the client's key is exchanged for a token (DocuSign, Salesforce). */
    JWT_BEARER("urn:ietf:params:oauth:grant-type:jwt-bearer"),
    /** RFC 6749 section 6: a refresh token from an earlier user consent is exchanged for a token (as with Jira 3LO). */
    REFRESH_TOKEN("refresh_token");

    private final String value;

    Grant(String value) {
        this.value = value;
    }

    /**
     * The grant's name on the wire.
     *
     * @return the value sent as the {@code grant_type} parameter
     */
    public String getValue() {
        return value;
    }
}
