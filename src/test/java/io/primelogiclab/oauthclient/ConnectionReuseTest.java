package io.primelogiclab.oauthclient;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLServerSocket;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * Kept-alive connections: reused per host and client certificate, never for token requests, never after a
 * request left them half-used, and never closed by a request another one has used them for since.
 */
@Timeout(60)
class ConnectionReuseTest {

    private final List<StubServer> servers = new ArrayList<StubServer>();

    @AfterEach
    void stopServers() {
        for (StubServer s : servers) {
            s.close();
        }
        UrlConnectionTransport.sendingFor(null);
    }

    @Test
    void serviceCallsInARowShareOneConnection() throws Exception {
        StubServer server = server(false);
        server.always("/items", StubServer.json(200, "{}"));
        OAuthServiceClient service = client(transport());

        service.get(server.url("/items"));
        service.post(server.url("/items"), "{}");
        service.put(server.url("/items"), "{}");
        service.delete(server.url("/items"));
        service.post(server.url("/items"), "{}");

        List<StubServer.Recorded> r = server.requests();
        assertEquals(5, r.size());
        assertEquals(1, ports(r).size(), "one TCP and TLS connection for all five calls: " + ports(r));
    }

    @Test
    void eachTokenRequestGetsAConnectionOfItsOwn() throws Exception {
        StubServer server = server(false);
        server.always("/token", StubServer.token("tok", 3600));
        server.always("/items", StubServer.json(200, "{}"));
        UrlConnectionTransport transport = transport();
        TokenClient tokens = new TokenClient(executor(transport), Clock.systemUTC());
        ClientInfo info = ClientInfo.forTenant("svc", "acme").tokenUrl(server.url("/token"))
                .clientId("id").clientSecret("s").build();

        tokens.fetch(info, Collections.<String>emptyList());
        tokens.fetch(info, Collections.<String>emptyList());
        executor(transport).execute(() -> HttpRequest.get(server.url("/items"), headers()), HttpExecutor.Retry.NEVER);

        List<StubServer.Recorded> r = server.requests();
        assertEquals(3, r.size());
        assertEquals(3, ports(r).size(), "two token requests and a service call, three connections: " + ports(r));
    }

    @Test
    void aConnectionIsReusedOnlyWithItsOwnClientCertificate() throws Exception {
        StubServer server = new StubServer(TestTls.serverContext(), false, true);
        servers.add(server);
        server.always("/items", StubServer.json(200, "{}"));
        UrlConnectionTransport transport = transport();
        ClientKey tenantA = Fixtures.clientWithChain();
        ClientKey tenantB = Fixtures.clientWithChain(); // the same certificate, another tenant's key object

        send(transport, server, tenantA);
        send(transport, server, tenantB);
        send(transport, server, null);
        send(transport, server, tenantA);
        send(transport, server, null);

        List<StubServer.Recorded> r = server.requests();
        assertEquals(5, r.size());
        assertEquals(3, new HashSet<Integer>(Arrays.asList(r.get(0).clientPort, r.get(1).clientPort,
                r.get(2).clientPort)).size(), "tenant A, tenant B and no certificate never share a connection");
        assertEquals(r.get(0).clientPort, r.get(3).clientPort, "tenant A's second call reuses tenant A's connection");
        assertEquals(r.get(2).clientPort, r.get(4).clientPort, "a call without a certificate reuses that one's");
        assertNotNull(r.get(0).clientCertificate);
        assertNotNull(r.get(1).clientCertificate);
        assertNull(r.get(2).clientCertificate, "no tenant's certificate on a call without one");
        assertNotNull(r.get(3).clientCertificate);
        assertNull(r.get(4).clientCertificate);
    }

    @Test
    void anAnswerOverTheSizeLimitClosesItsConnection() throws Exception {
        StubServer server = server(false);
        byte[] big = new byte[2048];
        Arrays.fill(big, (byte) 'x');
        // the rest comes later: closing the stream alone would have the JDK read it in the background and
        // then keep the connection for the next call
        server.always("/big", new StubServer.Response(200, "text/plain", big).stallAfter(1500, 300));
        server.always("/small", StubServer.json(200, "{}"));
        UrlConnectionTransport transport = transport();

        assertEquals(200, transport.execute(HttpRequest.get(server.url("/small"), headers())).getStatus());
        IOException tooBig = assertThrows(IOException.class, () ->
                transport.execute(HttpRequest.get(server.url("/big"), headers()).withMaxResponseBytes(1024)));
        assertTrue(tooBig.getMessage().contains("exceeds 1024 bytes"), tooBig.getMessage());
        Thread.sleep(600); // past the stall: the rest of the big answer has been sent
        assertEquals(200, transport.execute(HttpRequest.get(server.url("/small"), headers())).getStatus());

        List<StubServer.Recorded> r = server.requests();
        assertEquals(r.get(0).clientPort, r.get(1).clientPort, "the big answer came on the kept-alive connection");
        assertNotEquals(r.get(1).clientPort, r.get(2).clientPort, "and that connection was closed, not kept");
    }

    @Test
    void anAnswerCutOffAtTheDeadlineClosesItsConnection() throws Exception {
        StubServer server = server(false);
        byte[] slow = new byte[4096];
        Arrays.fill(slow, (byte) 'x');
        server.always("/slow", new StubServer.Response(200, "text/plain", slow).stallAfter(100, 1000));
        server.always("/small", StubServer.json(200, "{}"));
        UrlConnectionTransport transport = transport();

        assertEquals(200, transport.execute(HttpRequest.get(server.url("/small"), headers())).getStatus());
        assertThrows(IOException.class, () ->
                transport.execute(HttpRequest.get(server.url("/slow"), headers()).withTimeout(Duration.ofMillis(300))));
        assertEquals(200, transport.execute(HttpRequest.get(server.url("/small"), headers())).getStatus());

        List<StubServer.Recorded> r = server.requests();
        assertEquals(r.get(0).clientPort, r.get(1).clientPort);
        assertNotEquals(r.get(1).clientPort, r.get(2).clientPort, "the cut-off connection was closed, not kept");
    }

    @Test
    void aConnectionTheServerClosedWhileIdleIsNotUsed() throws Exception {
        try (ClosingServer server = new ClosingServer()) {
            UrlConnectionTransport transport = transport();
            String url = "https://localhost:" + server.port() + "/items";

            assertEquals(200, transport.execute(HttpRequest.get(url, headers())).getStatus());
            server.awaitClosed(1);
            // the JDK resends a GET once when the kept-alive connection turns out dead
            assertEquals(200, transport.execute(HttpRequest.get(url, headers())).getStatus());
            server.awaitClosed(2);
            // a POST is sent not resendable: the JDK checks the kept-alive connection is open before it
            HttpRequest post = new HttpRequest("POST", url, headers(), "{\"n\":1}".getBytes(StandardCharsets.UTF_8))
                    .notResendable();
            assertEquals(200, transport.execute(post).getStatus());

            assertEquals(Arrays.asList("GET", "GET", "POST {\"n\":1}"), server.requests(),
                    "each call reached the server once, the POST included");
        }
    }

    // ------------------------------------------------------------- ownership

    @Test
    void aLateDeadlineLeavesAConnectionAnotherRequestHasUsedSinceAlone() throws Exception {
        try (ServerSocket listener = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            Socket raw = new Socket(listener.getInetAddress(), listener.getLocalPort());
            Socket peer = listener.accept();
            UrlConnectionTransport.Call a = new UrlConnectionTransport.Call(0);
            UrlConnectionTransport.Call b = new UrlConnectionTransport.Call(0);

            UrlConnectionTransport.sendingFor(a);
            UrlConnectionTransport.TrackedSocket socket = UrlConnectionTransport.TrackedSocket.adopt(raw);
            socket.getOutputStream().write('a');
            assertSame(a, socket.user());

            // the JDK kept the connection alive and handed it to b before a's deadline came
            UrlConnectionTransport.sendingFor(b);
            socket.getOutputStream().write('b');
            assertSame(b, socket.user());

            UrlConnectionTransport.sendingFor(null);
            assertFalse(socket.closeFor(a));
            a.closeSockets();
            a.abandon();
            Thread.sleep(200); // abandon closes on a thread of its own
            assertFalse(raw.isClosed(), "a's deadline must not close the connection b is using");
            InputStream in = peer.getInputStream();
            assertEquals('a', in.read());
            assertEquals('b', in.read());

            b.abandon();
            waitUntilClosed(raw);
            peer.close();
        }
    }

    @Test
    void aFinishedRequestClosesNothingAndAGivenUpOneClosesWhatItTouches() throws Exception {
        try (ServerSocket listener = new ServerSocket(0, 2, InetAddress.getLoopbackAddress())) {
            Socket raw = new Socket(listener.getInetAddress(), listener.getLocalPort());
            Socket peer = listener.accept();
            UrlConnectionTransport.Call done = new UrlConnectionTransport.Call(0);

            UrlConnectionTransport.sendingFor(done);
            UrlConnectionTransport.TrackedSocket socket = UrlConnectionTransport.TrackedSocket.adopt(raw);
            socket.getOutputStream().write('x');
            done.finish();
            assertNull(socket.user(), "a finished request is no longer the socket's user");
            done.closeSockets();
            done.abandon();
            Thread.sleep(200);
            assertFalse(raw.isClosed(), "a finished request's deadline closes nothing");

            // a request given up at its deadline that still reads or writes closes the socket at once
            UrlConnectionTransport.Call late = new UrlConnectionTransport.Call(0);
            late.abandon();
            UrlConnectionTransport.sendingFor(late);
            assertThrows(SocketException.class, () -> socket.getOutputStream().write('y'));
            assertTrue(raw.isClosed());

            // and a socket made for one is closed as it is made
            Socket other = new Socket(listener.getInetAddress(), listener.getLocalPort());
            UrlConnectionTransport.TrackedSocket.adopt(other);
            assertTrue(other.isClosed());
            peer.close();
        }
    }

    // -------------------------------------------------------------- helpers

    private static void waitUntilClosed(Socket socket) throws InterruptedException {
        long end = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (!socket.isClosed() && System.nanoTime() < end) {
            Thread.sleep(10);
        }
        assertTrue(socket.isClosed(), "the socket should have been closed");
    }

    private static void send(UrlConnectionTransport transport, StubServer server, ClientKey certificate)
            throws IOException {
        HttpResponse response = transport.execute(HttpRequest.get(server.url("/items"), headers())
                .withClientCertificate(certificate));
        assertEquals(200, response.getStatus());
    }

    private static java.util.Set<Integer> ports(List<StubServer.Recorded> requests) {
        java.util.Set<Integer> ports = new java.util.LinkedHashSet<Integer>();
        for (StubServer.Recorded r : requests) {
            ports.add(r.clientPort);
        }
        return ports;
    }

    private static Map<String, String> headers() {
        return new LinkedHashMap<String, String>();
    }

    /** A transport of its own: the JDK keeps connections per TLS socket factory, so tests don't share them. */
    private static UrlConnectionTransport transport() {
        return new UrlConnectionTransport(Duration.ofSeconds(5), Duration.ofSeconds(10), Duration.ofSeconds(20),
                TestTls.clientTrust());
    }

    private static HttpExecutor executor(UrlConnectionTransport transport) {
        return new HttpExecutor(transport, 0, Duration.ZERO, HttpExecutor.THREAD_SLEEPER, Duration.ofSeconds(20));
    }

    private static OAuthServiceClient client(UrlConnectionTransport transport) {
        OAuthServiceClient service = new OAuthServiceClient(new TokenCache(), (info, scopes) -> {
            Map<String, Object> response = new LinkedHashMap<String, Object>();
            response.put("access_token", "tok");
            response.put("token_type", "Bearer");
            response.put("expires_in", 3600);
            return AccessToken.fromResponse(response, Instant.now());
        }, executor(transport), OAuthServiceClient.MAX_RESPONSE_BYTES);
        service.initialize(ClientInfo.forTenant("svc", "acme").tokenUrl("https://login.example.com/token")
                .clientId("id").clientSecret("s").build());
        return service;
    }

    private StubServer server(boolean needClientAuth) throws IOException {
        StubServer s = new StubServer(TestTls.serverContext(), needClientAuth);
        servers.add(s);
        return s;
    }

    /**
     * A TLS server that answers one request per connection with a keep-alive answer, then closes the
     * connection without saying so, as a server does when its idle timeout ends.
     */
    private static final class ClosingServer implements AutoCloseable {

        private final SSLServerSocket listener;
        private final List<String> requests = Collections.synchronizedList(new ArrayList<String>());
        private final List<CountDownLatch> closed = new ArrayList<CountDownLatch>();
        private final Thread acceptor;

        ClosingServer() throws IOException {
            listener = (SSLServerSocket) TestTls.serverContext().getServerSocketFactory()
                    .createServerSocket(0, 10, InetAddress.getLoopbackAddress());
            for (int i = 0; i < 10; i++) {
                closed.add(new CountDownLatch(1));
            }
            acceptor = new Thread(this::serve, "closing-server");
            acceptor.setDaemon(true);
            acceptor.start();
        }

        int port() {
            return listener.getLocalPort();
        }

        List<String> requests() {
            synchronized (requests) {
                return new ArrayList<String>(requests);
            }
        }

        /** Waits until the {@code n}th connection was closed, and its close reached the client. */
        void awaitClosed(int n) throws InterruptedException {
            assertTrue(closed.get(n - 1).await(5, TimeUnit.SECONDS), "connection " + n + " not closed");
            Thread.sleep(100);
        }

        private void serve() {
            int n = 0;
            while (!listener.isClosed()) {
                try (Socket s = listener.accept()) {
                    String head = readHead(s.getInputStream());
                    if (head.isEmpty()) {
                        continue; // a connection the client opened and dropped
                    }
                    String request = head.substring(0, head.indexOf(' '));
                    int length = contentLength(head);
                    if (length > 0) {
                        byte[] body = new byte[length];
                        int read = 0;
                        while (read < length) {
                            int r = s.getInputStream().read(body, read, length - read);
                            if (r < 0) {
                                break;
                            }
                            read += r;
                        }
                        request += " " + new String(body, 0, read, StandardCharsets.UTF_8);
                    }
                    requests.add(request);
                    OutputStream out = s.getOutputStream();
                    out.write(("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok")
                            .getBytes(StandardCharsets.US_ASCII));
                    out.flush();
                    Thread.sleep(50); // the answer reaches the client, which keeps the connection alive
                } catch (IOException | InterruptedException e) {
                    if (listener.isClosed()) {
                        return;
                    }
                } finally {
                    if (n < closed.size()) {
                        closed.get(n).countDown();
                    }
                    n++;
                }
            }
        }

        private static String readHead(InputStream in) throws IOException {
            ByteArrayOutputStream head = new ByteArrayOutputStream();
            int c;
            while ((c = in.read()) != -1) {
                head.write(c);
                byte[] b = head.toByteArray();
                int len = b.length;
                if (len >= 4 && b[len - 4] == '\r' && b[len - 3] == '\n' && b[len - 2] == '\r' && b[len - 1] == '\n') {
                    break;
                }
            }
            return new String(head.toByteArray(), StandardCharsets.US_ASCII);
        }

        private static int contentLength(String head) {
            for (String line : head.split("\r\n")) {
                if (line.toLowerCase(java.util.Locale.ROOT).startsWith("content-length:")) {
                    return Integer.parseInt(line.substring(15).trim());
                }
            }
            return 0;
        }

        @Override
        public void close() throws IOException {
            listener.close();
        }
    }
}
