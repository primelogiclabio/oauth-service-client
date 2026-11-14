package io.primelogiclab.oauthclient;

import static org.junit.jupiter.api.Assertions.assertEquals;
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
