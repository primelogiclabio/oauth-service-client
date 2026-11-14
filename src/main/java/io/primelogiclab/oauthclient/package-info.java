/**
 * Calls OAuth-protected external services (DocuSign, Salesforce, Jira, ...) for backend code. The
 * caller passes client info for one service and tenant (or for all tenants), then the endpoint and
 * payload; the library gets the access token, caches it per service and tenant until shortly before
 * it expires, and makes the request. Every HTTP answer goes back to the caller; only failures without
 * an answer raise exceptions.
 */
package io.primelogiclab.oauthclient;
