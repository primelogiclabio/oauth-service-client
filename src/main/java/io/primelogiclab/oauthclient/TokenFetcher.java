package io.primelogiclab.oauthclient;

import java.util.List;

/** Gets a new token from a service's token endpoint; the {@link TokenCache} decides when. */
@FunctionalInterface
interface TokenFetcher {

    /**
     * @param scopes the scopes to ask for, already checked: the app's for this request, else the client
     *               info's defaults; empty for none
     * @return the new token, never {@code null}
     * @throws RuntimeException when no token could be had; the cache passes it on unchanged
     */
    AccessToken fetch(ClientInfo clientInfo, List<String> scopes);
}
