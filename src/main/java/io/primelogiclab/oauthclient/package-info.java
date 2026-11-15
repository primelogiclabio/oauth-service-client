/**
 * Calls OAuth-protected external services (DocuSign, Salesforce, Jira, ...) for backend code. Start with
 * {@link io.primelogiclab.oauthclient.OAuthServiceClient}: initialize it with a
 * {@link io.primelogiclab.oauthclient.ClientInfo} for one service and tenant (or for all tenants), then
 * call {@code get}, {@code post}, {@code put}, {@code patch}, {@code delete} or {@code request(ServiceRequest)}. The
 * library gets the access token, caches it per service, tenant, user and scopes until shortly before it
 * expires, and makes the request. Every HTTP answer goes back to the caller as a
 * {@link io.primelogiclab.oauthclient.ServiceResponse}; only failures without an answer throw
 * {@link io.primelogiclab.oauthclient.OAuthServiceException}.
 */
package io.primelogiclab.oauthclient;
