package io.primelogiclab.oauthclient;

import java.util.Map;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.IOException;
import java.net.Authenticator;
import java.net.InetAddress;
import java.net.PasswordAuthentication;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/** The transport's defences against hostile servers and against JVM-wide settings made by other code. */
@Timeout(60)
class TransportSecurityTest {

    @Test
    void aStalledTlsHandshakeEndsAtTheDeadline() throws Exception {
        // accepts TCP connections and never answers, so the TLS handshake waits for the server's first message
        final List<Socket> held = Collections.synchronizedList(new ArrayList<Socket>());
        try (final ServerSocket silent = new ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"))) {
            Thread acceptor = new Thread(() -> {
                try {
                    while (true) {
                        held.add(silent.accept());
                    }
                } catch (IOException closed) {
                    // the test is over
                }
            });
            acceptor.setDaemon(true);
            acceptor.start();
            String host = "127.0.0.1:" + silent.getLocalPort();
            UrlConnectionTransport transport = new UrlConnectionTransport(Duration.ofSeconds(5), Duration.ofSeconds(30),
                    Duration.ofSeconds(1), TestTls.clientTrust());

            long start = System.nanoTime();
            assertThrows(IOException.class, () -> transport.execute(HttpRequest.get("https://" + host + "/x",
                    Collections.<String, String>emptyMap())));
            assertTrue(System.nanoTime() - start < Duration.ofSeconds(5).toNanos(), "the caller waited past the deadline");

            // the worker gives the host slot back soon after the deadline, not after the 30 s read timeout
            long until = System.nanoTime() + Duration.ofSeconds(5).toNanos();
            while (UrlConnectionTransport.inFlight(host) > 0 && System.nanoTime() < until) {
                Thread.sleep(50);
            }
            assertEquals(0, UrlConnectionTransport.inFlight(host), "the stalled handshake still holds its worker");
        } finally {
            for (Socket s : held) {
                s.close();
            }
        }
    }

    @Test
    void aTrustAllDefaultInstalledByOtherCodeIsNotUsed() throws Exception {
        SSLSocketFactory jvmDefault = HttpsURLConnection.getDefaultSSLSocketFactory();
        HostnameVerifier jvmVerifier = HttpsURLConnection.getDefaultHostnameVerifier();
        try (StubServer server = new StubServer(TestTls.serverContext(), false)) {
            server.always("/x", StubServer.json(200, "{}"));
            SSLContext trustAll = SSLContext.getInstance("TLS");
            trustAll.init(null, new TrustManager[] {new TrustEverything()}, null);
            HttpsURLConnection.setDefaultSSLSocketFactory(trustAll.getSocketFactory());
            HttpsURLConnection.setDefaultHostnameVerifier((h, s) -> true);
            // the JVM's trust store doesn't know the test CA, so the stub server must be refused
            UrlConnectionTransport transport = new UrlConnectionTransport(Duration.ofSeconds(5), Duration.ofSeconds(10),
                    Duration.ofSeconds(20), null);

            IOException e = assertThrows(IOException.class, () -> transport.execute(HttpRequest.get(server.url("/x"),
                    Collections.<String, String>emptyMap())));

            assertTrue(HttpExecutor.tlsHandshakeFailed(e), String.valueOf(e));
            assertTrue(server.requests().isEmpty());
        } finally {
            HttpsURLConnection.setDefaultSSLSocketFactory(jvmDefault);
            HttpsURLConnection.setDefaultHostnameVerifier(jvmVerifier);
        }
    }

    @Test
    void everyTlsSocketChecksTheHostName() throws Exception {
        try (ServerSocket listener = new ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"));
             Socket plain = new Socket("127.0.0.1", listener.getLocalPort());
             Socket accepted = listener.accept()) {
            SSLSocketFactory factory = UrlConnectionTransport.CallSocketFactory.untracked(
                    Tls.socketFactory(null, TestTls.clientTrust()));

            SSLSocket tls = (SSLSocket) factory.createSocket(plain, "localhost", listener.getLocalPort(), false);

            assertEquals("HTTPS", tls.getSSLParameters().getEndpointIdentificationAlgorithm());
        }
    }

    @Test
    void aServiceLoginChallengeNeverReachesTheJvmsAuthenticator() throws Exception {
        assumeTrue(UrlConnectionTransport.refusesServerAuthentication(), "Java 8 has no per-connection Authenticator");
        final AtomicInteger asked = new AtomicInteger();
        Authenticator.setDefault(new Authenticator() {
            @Override
            protected PasswordAuthentication getPasswordAuthentication() {
                asked.incrementAndGet();
                return new PasswordAuthentication("app", "app-proxy-password".toCharArray());
            }
        });
        try (StubServer server = new StubServer(TestTls.serverContext(), false)) {
            server.always("/x", new StubServer.Response(401, "text/plain", "login")
                    .header("WWW-Authenticate", "Basic realm=\"service\""));
            UrlConnectionTransport transport = new UrlConnectionTransport(Duration.ofSeconds(5), Duration.ofSeconds(10),
                    Duration.ofSeconds(20), TestTls.clientTrust());

            HttpResponse response = transport.execute(HttpRequest.get(server.url("/x"), Collections.<String, String>emptyMap()));

            assertEquals(401, response.getStatus());
            assertEquals(0, asked.get(), "the JVM's Authenticator was asked for the service's login");
            assertEquals(1, server.requests().size());
        } finally {
            Authenticator.setDefault(null);
        }
    }

    @Test
    void eachClientCertificateGetsOneSocketFactoryOfItsOwn() {
        UrlConnectionTransport transport = new UrlConnectionTransport(Duration.ofSeconds(5), Duration.ofSeconds(10),
                Duration.ofSeconds(20), TestTls.clientTrust());
        ClientKey tenantA = Fixtures.clientWithChain();
        ClientKey tenantB = Fixtures.clientWithChain(); // the same certificate, another key object

        SSLSocketFactory a = transport.socketFactoryFor(tenantA);

        org.junit.jupiter.api.Assertions.assertSame(a, transport.socketFactoryFor(tenantA));
        org.junit.jupiter.api.Assertions.assertNotSame(a, transport.socketFactoryFor(tenantB));
    }

    @Test
    void aPatchUsesTheSameTlsAndLoginRules() throws Exception {
        assumeTrue(UrlConnectionTransport.patchSupported(), "PATCH needs Java 11");
        Map<String, String> json = Collections.singletonMap("Content-Type", "application/json");
        SSLSocketFactory jvmDefault = HttpsURLConnection.getDefaultSSLSocketFactory();
        final AtomicInteger asked = new AtomicInteger();
        try (StubServer server = new StubServer(TestTls.serverContext(), false)) {
            server.always("/x", new StubServer.Response(401, "text/plain", "login")
                    .header("WWW-Authenticate", "Basic realm=\"service\""));
            SSLContext trustAll = SSLContext.getInstance("TLS");
            trustAll.init(null, new TrustManager[] {new TrustEverything()}, null);
            HttpsURLConnection.setDefaultSSLSocketFactory(trustAll.getSocketFactory());
            Authenticator.setDefault(new Authenticator() {
                @Override
                protected PasswordAuthentication getPasswordAuthentication() {
                    asked.incrementAndGet();
                    return new PasswordAuthentication("app", "app-proxy-password".toCharArray());
                }
            });

            // the JVM's trust store doesn't know the test CA: refused, trust-all default or not
            UrlConnectionTransport jvmTrust = new UrlConnectionTransport(Duration.ofSeconds(5), Duration.ofSeconds(10),
                    Duration.ofSeconds(20), null);
            IOException e = assertThrows(IOException.class,
                    () -> jvmTrust.execute(new HttpRequest("PATCH", server.url("/x"), json, "{}".getBytes("UTF-8"))));
            assertTrue(HttpExecutor.tlsHandshakeFailed(e), String.valueOf(e));

            // with the test CA: the 401 login challenge comes back, the JVM's Authenticator never asked
            UrlConnectionTransport testTrust = new UrlConnectionTransport(Duration.ofSeconds(5), Duration.ofSeconds(10),
                    Duration.ofSeconds(20), TestTls.clientTrust());
            HttpResponse response = testTrust.execute(new HttpRequest("PATCH", server.url("/x"), json, "{}".getBytes("UTF-8")));
            assertEquals(401, response.getStatus());
            assertEquals(0, asked.get());
            assertEquals(1, server.requests().size());

            // one JDK client per client certificate
            Object patch = testTrust.patchTransport();
            java.lang.reflect.Method clientFor = patch.getClass().getDeclaredMethod("clientFor", ClientKey.class);
            ClientKey key = Fixtures.clientWithChain();
            org.junit.jupiter.api.Assertions.assertSame(clientFor.invoke(patch, key), clientFor.invoke(patch, key));
            org.junit.jupiter.api.Assertions.assertNotSame(clientFor.invoke(patch, key),
                    clientFor.invoke(patch, Fixtures.clientWithChain()));
        } finally {
            HttpsURLConnection.setDefaultSSLSocketFactory(jvmDefault);
            Authenticator.setDefault(null);
        }
    }

    @Test
    void onlyTheTransportsOwnNotSentCounts() {
        assertTrue(HttpExecutor.notSent(new RequestNotSentException("not sent", null)));
        // a plain connection error can come from the JDK's own resend after the request was sent
        assertFalse(HttpExecutor.notSent(new java.net.ConnectException("refused")));
        assertFalse(HttpExecutor.notSent(new java.net.UnknownHostException("gone")));
    }

    @Test
    void aJvmWideCookieHandlerIsWarnedAboutOnce() throws Exception {
        final List<String> warnings = Collections.synchronizedList(new ArrayList<String>());
        java.util.logging.Logger log = java.util.logging.Logger.getLogger(UrlConnectionTransport.class.getName());
        java.util.logging.Handler handler = new java.util.logging.Handler() {
            @Override
            public void publish(java.util.logging.LogRecord record) {
                if (record.getLevel() == java.util.logging.Level.WARNING) {
                    warnings.add(record.getMessage());
                }
            }

            @Override
            public void flush() {
            }

            @Override
            public void close() {
            }
        };
        log.addHandler(handler);
        UrlConnectionTransport.resetCookieWarning();
        java.net.CookieHandler.setDefault(new java.net.CookieManager());
        try (StubServer server = new StubServer(TestTls.serverContext(), false)) {
            server.always("/x", StubServer.json(200, "{}"));
            UrlConnectionTransport transport = new UrlConnectionTransport(Duration.ofSeconds(5), Duration.ofSeconds(10),
                    Duration.ofSeconds(20), TestTls.clientTrust());
            transport.execute(HttpRequest.get(server.url("/x"), Collections.<String, String>emptyMap()));
            transport.execute(HttpRequest.get(server.url("/x"), Collections.<String, String>emptyMap()));
        } finally {
            java.net.CookieHandler.setDefault(null);
            log.removeHandler(handler);
            UrlConnectionTransport.resetCookieWarning();
        }
        assertEquals(1, warnings.size(), String.valueOf(warnings));
        assertTrue(warnings.get(0).contains("CookieHandler"), warnings.get(0));
    }

    @Test
    void thePatchClientChecksHostNamesItselfAndRunsOnTheLibrarysThreads() throws Exception {
        assumeTrue(UrlConnectionTransport.patchSupported(), "PATCH needs Java 11");
        UrlConnectionTransport transport = new UrlConnectionTransport(Duration.ofSeconds(5), Duration.ofSeconds(10),
                Duration.ofSeconds(20), TestTls.clientTrust());
        Object patch = transport.patchTransport();
        java.lang.reflect.Method clientFor = patch.getClass().getDeclaredMethod("clientFor", ClientKey.class);
        Object plain = clientFor.invoke(patch, (ClientKey) null);
        Object withKey = clientFor.invoke(patch, Fixtures.clientWithChain());
        for (Object client : new Object[] {plain, withKey}) {
            javax.net.ssl.SSLParameters params = (javax.net.ssl.SSLParameters) Class.forName("java.net.http.HttpClient").getMethod("sslParameters")
                    .invoke(client);
            assertEquals("HTTPS", params.getEndpointIdentificationAlgorithm(),
                    "set on the client, so a JVM-wide switch can't turn host name checks off");
            java.util.Optional<?> executor = (java.util.Optional<?>) Class.forName("java.net.http.HttpClient").getMethod("executor").invoke(client);
            assertTrue(executor.isPresent(), "the library's own threads");
        }
        assertEquals(((java.util.Optional<?>) Class.forName("java.net.http.HttpClient").getMethod("executor").invoke(plain)).get(),
                ((java.util.Optional<?>) Class.forName("java.net.http.HttpClient").getMethod("executor").invoke(withKey)).get());
    }

    private static final class TrustEverything implements X509TrustManager {
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) {
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) {
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    }
}
