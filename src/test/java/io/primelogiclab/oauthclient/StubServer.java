package io.primelogiclab.oauthclient;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Deque;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLPeerUnverifiedException;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsExchange;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;

/**
 * Tiny scripted HTTPS server for tests (JDK built-in, works on Java 8 and 21), with the test CA's server
 * certificate for {@code localhost}. Copied from oauth-connector, HTTPS only.
 */
final class StubServer implements AutoCloseable {

    static final class Response {
        final int status;
        final String contentType;
        final byte[] body;
        final Map<String, String> headers = new LinkedHashMap<String, String>();

        Response(int status, String contentType, String body) {
            this(status, contentType, body.getBytes(StandardCharsets.UTF_8));
        }

        Response(int status, String contentType, byte[] body) {
            this.status = status;
            this.contentType = contentType;
            this.body = body;
        }

        Response header(String name, String value) {
            headers.put(name, value);
            return this;
        }
    }

    static final class Recorded {
        final String method;
        final String path;
        final Map<String, String> headers;
        final String body;
        final byte[] bodyBytes;
        /** Client certificate presented on the TLS connection, or {@code null}. */
        final X509Certificate clientCertificate;

        Recorded(String method, String path, Map<String, String> headers, byte[] body, X509Certificate clientCertificate) {
            this.method = method;
            this.path = path;
            this.headers = headers;
            this.bodyBytes = body;
            this.body = new String(body, StandardCharsets.UTF_8);
            this.clientCertificate = clientCertificate;
        }

        String header(String name) {
            return headers.get(name.toLowerCase(Locale.ROOT));
        }

        /** The form fields in the order sent; a repeated name keeps its first value. */
        Map<String, String> form() {
            Map<String, String> m = new LinkedHashMap<String, String>();
            if (body.isEmpty()) {
                return m;
            }
            for (String pair : body.split("&")) {
                int i = pair.indexOf('=');
                try {
                    String k = URLDecoder.decode(pair.substring(0, i), "UTF-8");
                    String v = URLDecoder.decode(pair.substring(i + 1), "UTF-8");
                    if (!m.containsKey(k)) {
                        m.put(k, v);
                    }
                } catch (UnsupportedEncodingException e) {
                    throw new IllegalStateException(e);
                }
            }
            return m;
        }

        String param(String name) {
            return form().get(name);
        }
    }

    private final HttpsServer server;
    private final Map<String, Deque<Response>> queued = new HashMap<String, Deque<Response>>();
    private final Map<String, Response> fixed = new HashMap<String, Response>();
    private final List<Recorded> requests = Collections.synchronizedList(new ArrayList<Recorded>());

    /** With {@code needClientAuth} the TLS handshake fails without a client certificate the test CA issued. */
    StubServer(final SSLContext tls, final boolean needClientAuth) throws IOException {
        server = HttpsServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(tls) {
            @Override
            public void configure(HttpsParameters params) {
                SSLParameters p = tls.getDefaultSSLParameters();
                p.setNeedClientAuth(needClientAuth);
                params.setSSLParameters(p);
            }
        });
        server.createContext("/", this::handle);
        server.start();
    }

    String url(String path) {
        return "https://localhost:" + server.getAddress().getPort() + path;
    }

    /** Response returned for every request to the path, unless something is queued. */
    synchronized StubServer always(String path, Response response) {
        fixed.put(path, response);
        return this;
    }

    /** Response returned once, in order. */
    synchronized StubServer enqueue(String path, Response response) {
        Deque<Response> q = queued.get(path);
        if (q == null) {
            q = new ArrayDeque<Response>();
            queued.put(path, q);
        }
        q.add(response);
        return this;
    }

    static Response json(int status, String body) {
        return new Response(status, "application/json", body);
    }

    static Response token(String accessToken, long expiresIn) {
        return json(200, "{\"access_token\":\"" + accessToken + "\",\"token_type\":\"Bearer\",\"expires_in\":" + expiresIn + "}");
    }

    List<Recorded> requests() {
        synchronized (requests) {
            return new ArrayList<Recorded>(requests);
        }
    }

    Recorded last() {
        List<Recorded> r = requests();
        return r.isEmpty() ? null : r.get(r.size() - 1);
    }

    private void handle(HttpExchange ex) throws IOException {
        try {
            String path = ex.getRequestURI().getPath();
            Map<String, String> headers = new HashMap<String, String>();
            for (Map.Entry<String, List<String>> e : ex.getRequestHeaders().entrySet()) {
                headers.put(e.getKey().toLowerCase(Locale.ROOT), e.getValue().get(0));
            }
            X509Certificate clientCert = null;
            try {
                Certificate[] peer = ((HttpsExchange) ex).getSSLSession().getPeerCertificates();
                clientCert = (X509Certificate) peer[0];
            } catch (SSLPeerUnverifiedException none) {
                // no client certificate presented
            }
            requests.add(new Recorded(ex.getRequestMethod(), path, headers, read(ex.getRequestBody()), clientCert));

            Response r;
            synchronized (this) {
                Deque<Response> q = queued.get(path);
                r = q != null && !q.isEmpty() ? q.poll() : fixed.get(path);
            }
            if (r == null) {
                r = new Response(404, "text/plain", "not found");
            }
            byte[] bytes = "HEAD".equals(ex.getRequestMethod()) ? new byte[0] : r.body;
            if (r.contentType != null) {
                ex.getResponseHeaders().add("Content-Type", r.contentType);
            }
            for (Map.Entry<String, String> h : r.headers.entrySet()) {
                ex.getResponseHeaders().add(h.getKey(), h.getValue());
            }
            ex.sendResponseHeaders(r.status, bytes.length == 0 ? -1 : bytes.length);
            if (bytes.length > 0) {
                OutputStream out = ex.getResponseBody();
                out.write(bytes);
                out.close();
            }
        } finally {
            ex.close();
        }
    }

    private static byte[] read(InputStream in) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        byte[] b = new byte[4096];
        int n;
        while ((n = in.read(b)) != -1) {
            buf.write(b, 0, n);
        }
        return buf.toByteArray();
    }

    @Override
    public void close() {
        server.stop(0);
    }
}
