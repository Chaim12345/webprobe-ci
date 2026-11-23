// Wire.java: the JSON-lines protocol between the bridge and WebProbe.
// stdout carries only protocol lines (replies, sendRequest calls, events);
// a reader thread takes WebProbe's lines from stdin, answers sendRequest
// replies directly and queues everything else for the main loop.

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

final class Wire {
    private Wire() {}

    static PrintStream out;
    /** Lines for the main loop (requests, responses, ping, shutdown). */
    static final BlockingQueue<Map<String, Object>> INBOX = new LinkedBlockingQueue<>();
    private static final Map<Integer, CompletableFuture<Map<String, Object>>> PENDING = new ConcurrentHashMap<>();
    private static final AtomicInteger NEXT_SID = new AtomicInteger(1);
    /** Marker queued when stdin closes. */
    static final Map<String, Object> EOF = Map.of("type", "shutdown");

    static void start() {
        out = new PrintStream(new java.io.FileOutputStream(java.io.FileDescriptor.out), true, StandardCharsets.UTF_8);
        // Extensions printing with System.out must not reach the protocol.
        System.setOut(System.err);
        Thread t = new Thread(() -> {
            try (BufferedReader in = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8))) {
                String line;
                while ((line = in.readLine()) != null) {
                    if (line.isBlank()) continue;
                    @SuppressWarnings("unchecked")
                    Map<String, Object> msg = (Map<String, Object>) Json.parse(line);
                    if ("sent".equals(msg.get("type"))) {
                        CompletableFuture<Map<String, Object>> f = PENDING.remove((int) num(msg.get("sid")));
                        if (f != null) f.complete(msg);
                    } else {
                        INBOX.add(msg);
                    }
                }
            } catch (Exception e) {
                Logs.error("[bridge] stdin reader: " + e);
            }
            INBOX.add(EOF);
        }, "bridge-stdin");
        t.setDaemon(true);
        t.start();
    }

    static synchronized void send(String line) {
        out.println(line);
    }

    /** Ask WebProbe to send `raw` to the service; the response bytes, or
     *  null with `error[0]` set. */
    static byte[] sendRequest(byte[] raw, String host, int port, boolean secure, String[] error) {
        int sid = NEXT_SID.getAndIncrement();
        CompletableFuture<Map<String, Object>> f = new CompletableFuture<>();
        PENDING.put(sid, f);
        send("{\"type\":\"send\",\"sid\":" + sid + ",\"raw\":" + Json.esc(b64(raw)) + ",\"host\":" + Json.esc(host)
                + ",\"port\":" + port + ",\"secure\":" + secure + "}");
        try {
            Map<String, Object> r = f.get(120, TimeUnit.SECONDS);
            Object resp = r.get("raw");
            if (resp instanceof String s) return unb64(s);
            error[0] = String.valueOf(r.getOrDefault("error", "no response"));
            return null;
        } catch (Exception e) {
            PENDING.remove(sid);
            error[0] = "WebProbe did not answer: " + e;
            return null;
        }
    }

    /** Ask WebProbe's engine for something (`op` with JSON `args`); the
     *  result value, or IllegalStateException with WebProbe's message. */
    static Object call(String op, String args) {
        int sid = NEXT_SID.getAndIncrement();
        CompletableFuture<Map<String, Object>> f = new CompletableFuture<>();
        PENDING.put(sid, f);
        send("{\"type\":\"call\",\"sid\":" + sid + ",\"op\":" + Json.esc(op) + ",\"args\":" + (args == null ? "{}" : args) + "}");
        Map<String, Object> r;
        try {
            r = f.get(120, TimeUnit.SECONDS);
        } catch (Exception e) {
            PENDING.remove(sid);
            throw new IllegalStateException("WebProbe did not answer " + op + ": " + e);
        }
        if (r.get("error") != null) throw new IllegalStateException(String.valueOf(r.get("error")));
        return r.get("result");
    }

    static void event(String level, String message) {
        send("{\"type\":\"event\",\"level\":" + Json.esc(level) + ",\"message\":" + Json.esc(message) + "}");
    }

    static String b64(byte[] b) { return Base64.getEncoder().encodeToString(b); }
    static byte[] unb64(String s) { return Base64.getDecoder().decode(s); }

    static double num(Object o) { return o instanceof Number n ? n.doubleValue() : 0; }

    static String str(Map<String, Object> m, String k, String dflt) {
        Object v = m.get(k);
        return v == null ? dflt : String.valueOf(v);
    }

    /** Minimal JSON reader / string escaper. */
    static final class Json {
        final String s;
        int i;
        Json(String s) { this.s = s; }
        static Object parse(String text) { Json j = new Json(text); j.ws(); return j.value(); }
        void ws() { while (i < s.length() && Character.isWhitespace(s.charAt(i))) i++; }
        char peek() { return s.charAt(i); }
        Object value() {
            ws();
            switch (peek()) {
                case '{': return obj();
                case '[': return arr();
                case '"': return str();
                case 't': i += 4; return Boolean.TRUE;
                case 'f': i += 5; return Boolean.FALSE;
                case 'n': i += 4; return null;
                default: return num();
            }
        }
        Map<String, Object> obj() {
            Map<String, Object> m = new java.util.LinkedHashMap<>();
            i++; ws();
            if (peek() == '}') { i++; return m; }
            while (true) {
                ws();
                String k = str();
                ws(); expect(':');
                m.put(k, value());
                ws();
                char c = s.charAt(i++);
                if (c == '}') return m;
                if (c != ',') throw new IllegalArgumentException("bad object at " + i);
            }
        }
        List<Object> arr() {
            List<Object> l = new ArrayList<>();
            i++; ws();
            if (peek() == ']') { i++; return l; }
            while (true) {
                l.add(value());
                ws();
                char c = s.charAt(i++);
                if (c == ']') return l;
                if (c != ',') throw new IllegalArgumentException("bad array at " + i);
            }
        }
        String str() {
            expect('"');
            StringBuilder b = new StringBuilder();
            while (true) {
                char c = s.charAt(i++);
                if (c == '"') return b.toString();
                if (c == '\\') {
                    char e = s.charAt(i++);
                    switch (e) {
                        case 'n': b.append('\n'); break;
                        case 't': b.append('\t'); break;
                        case 'r': b.append('\r'); break;
                        case 'b': b.append('\b'); break;
                        case 'f': b.append('\f'); break;
                        case 'u': b.append((char) Integer.parseInt(s.substring(i, i + 4), 16)); i += 4; break;
                        default: b.append(e);
                    }
                } else b.append(c);
            }
        }
        double num() {
            int start = i;
            while (i < s.length() && "-+.eE0123456789".indexOf(s.charAt(i)) >= 0) i++;
            return Double.parseDouble(s.substring(start, i));
        }
        void expect(char c) {
            if (i >= s.length() || s.charAt(i) != c) throw new IllegalArgumentException("expected '" + c + "' at " + i);
            i++;
        }
        static String esc(String v) {
            if (v == null) return "null";
            StringBuilder b = new StringBuilder("\"");
            for (int k = 0; k < v.length(); k++) {
                char c = v.charAt(k);
                switch (c) {
                    case '"': b.append("\\\""); break;
                    case '\\': b.append("\\\\"); break;
                    case '\n': b.append("\\n"); break;
                    case '\r': b.append("\\r"); break;
                    case '\t': b.append("\\t"); break;
                    default:
                        if (c < 0x20) b.append(String.format("\\u%04x", (int) c));
                        else b.append(c);
                }
            }
            return b.append('"').toString();
        }
    }
}
