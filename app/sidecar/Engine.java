// Engine.java: the Montoya APIs WebProbe's engine answers (R-03 stages 4-5):
// scanner() checks run inside WebProbe's active and passive scans (their
// requests go through the scan's own send path); proxy() history, intercept
// and WebSocket handlers; scope(), siteMap(), repeater(), organizer(),
// comparer(), decoder(), intruder() payload generators and processors,
// collaborator(), websockets(), session handling actions and
// http().cookieJar(). Each call that needs WebProbe goes over the wire as
// {"type":"call","op":..}; WebProbe asks this JVM to run extension code
// with "scan-active", "scan-passive", "intruder-generate",
// "intruder-process", "ws-open", "ws-message" and "session-action".

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ScanCheck;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPointProvider;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.scanner.scancheck.ActiveScanCheck;
import burp.api.montoya.scanner.scancheck.PassiveScanCheck;
import burp.api.montoya.scanner.scancheck.ScanCheckType;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

@SuppressWarnings("deprecation")
final class Engine {
    private Engine() {}

    // ------------------------------------------------------------ JSON helpers

    static String msg(HttpRequest q, HttpResponse r) {
        HttpService s = q.httpService();
        return "{\"request\":" + Wire.Json.esc(Wire.b64(Messages.rawOf(q))) + ",\"host\":" + Wire.Json.esc(s == null ? "" : s.host())
                + ",\"port\":" + (s == null ? 80 : s.port()) + ",\"secure\":" + (s != null && s.secure())
                + (r == null ? "" : ",\"response\":" + Wire.Json.esc(Wire.b64(Messages.rawOf(r)))) + "}";
    }

    @SuppressWarnings("unchecked")
    static List<HttpRequestResponse> pairs(Object result) {
        List<HttpRequestResponse> out = new ArrayList<>();
        if (result instanceof List<?> l) for (Object o : l) out.add(Ui.pair((Map<String, Object>) o));
        return out;
    }

    // ------------------------------------------------------------ proxy(), scope(), siteMap(), tools

    static final List<Object> SCOPE_HANDLERS = new CopyOnWriteArrayList<>();

    @SuppressWarnings("unchecked")
    static Object historyItem(Map<String, Object> m) {
        HttpRequestResponse rr = Ui.pair(m);
        int id = (int) Wire.num(m.get("id"));
        return Api.obj()
                .on("request", a -> rr.request()).on("finalRequest", a -> rr.request())
                .on("response", a -> rr.response()).on("originalResponse", a -> rr.response())
                .on("hasResponse", a -> rr.response() != null)
                .on("annotations", a -> Messages.annotations(Wire.str(m, "notes", ""), MontoyaBridge.color(Wire.str(m, "highlight", ""))))
                .on("httpService", a -> rr.request().httpService())
                .on("url", a -> rr.request().url()).on("method", a -> rr.request().method()).on("path", a -> rr.request().path())
                .on("host", a -> rr.request().httpService().host()).on("port", a -> rr.request().httpService().port())
                .on("secure", a -> rr.request().httpService().secure())
                .on("httpServiceString", a -> rr.request().httpService().toString())
                .on("requestHttpVersion", a -> rr.request().httpVersion()).on("requestBody", a -> rr.request().bodyToString())
                .on("edited", a -> Boolean.TRUE.equals(m.get("edited")))
                .on("time", a -> java.time.ZonedDateTime.ofInstant(java.time.Instant.ofEpochSecond((long) Wire.num(m.get("time"))), java.time.ZoneOffset.UTC))
                .on("listenerPort", a -> (int) Wire.num(m.get("listenerPort")))
                .on("id", a -> id)
                .on("contains", a -> a[0] instanceof java.util.regex.Pattern p ? rr.request().contains(p) || (rr.response() != null && rr.response().contains(p))
                        : rr.request().contains((String) a[0], (Boolean) a[1]) || (rr.response() != null && rr.response().contains((String) a[0], (Boolean) a[1])))
                .text(rr.request().url())
                .as(burp.api.montoya.proxy.ProxyHttpRequestResponse.class);
    }

    @SuppressWarnings({ "unchecked", "rawtypes" })
    static List<Object> filtered(List<Object> items, Object filter, String method) {
        if (filter == null) return items;
        List<Object> out = new ArrayList<>();
        for (Object o : items) {
            try {
                // The filter interface's own method (a lambda's class is not accessible).
                java.lang.reflect.Method m = null;
                for (Class<?> i : filter.getClass().getInterfaces())
                    for (java.lang.reflect.Method x : i.getMethods()) if (x.getName().equals(method) && x.getParameterCount() == 1) m = x;
                if (m != null && Boolean.TRUE.equals(m.invoke(filter, o))) out.add(o);
            } catch (Exception e) {
                Logs.error("[bridge] history filter failed: " + e);
            }
        }
        return out;
    }

    @SuppressWarnings("unchecked")
    static List<Object> history() {
        List<Object> out = new ArrayList<>();
        Object r = Wire.call("proxy.history", null);
        if (r instanceof List<?> l) for (Object o : l) out.add(historyItem((Map<String, Object>) o));
        return out;
    }

    @SuppressWarnings("unchecked")
    static List<Object> wsHistory() {
        List<Object> out = new ArrayList<>();
        Object r = Wire.call("proxy.ws-history", null);
        if (r instanceof List<?> l) {
            for (Object o : l) {
                Map<String, Object> m = (Map<String, Object>) o;
                String dir = Wire.str(m, "direction", "");
                out.add(Api.obj()
                        .on("id", a -> (int) Wire.num(m.get("id")))
                        .on("payload", a -> Messages.bytes(Wire.str(m, "payload", "").getBytes(Messages.L1)))
                        .on("direction", a -> Enum.valueOf(burp.api.montoya.websocket.Direction.class, dir.toLowerCase().startsWith("out") || dir.contains("client") ? "CLIENT_TO_SERVER" : "SERVER_TO_CLIENT"))
                        .on("time", a -> java.time.ZonedDateTime.ofInstant(java.time.Instant.ofEpochSecond((long) Wire.num(m.get("time"))), java.time.ZoneOffset.UTC))
                        .on("annotations", a -> Messages.annotations("", HighlightColor.NONE))
                        .text(Wire.str(m, "payload", ""))
                        .as(burp.api.montoya.proxy.ProxyWebSocketMessage.class));
            }
        }
        return out;
    }

    static void proxyApi(Api.Obj o) {
        o.on("history", 0, a -> history())
         .on("history", 1, a -> filtered(history(), a[0], "matches"))
         .on("webSocketHistory", 0, a -> wsHistory())
         .on("webSocketHistory", 1, a -> filtered(wsHistory(), a[0], "matches"))
         .on("enableIntercept", a -> { Wire.call("proxy.intercept", "{\"on\":true}"); return null; })
         .on("disableIntercept", a -> { Wire.call("proxy.intercept", "{\"on\":false}"); return null; })
         .on("isInterceptEnabled", a -> Boolean.TRUE.equals(Wire.call("proxy.intercept-state", null)))
         .on("registerWebSocketCreationHandler", a -> reg(WS_PROXY_CREATION, (burp.api.montoya.proxy.websocket.ProxyWebSocketCreationHandler) a[0]));
    }

    // ------------------------------------------------------------ WebSockets

    static final List<burp.api.montoya.proxy.websocket.ProxyWebSocketCreationHandler> WS_PROXY_CREATION = new CopyOnWriteArrayList<>();
    static final List<burp.api.montoya.websocket.WebSocketCreatedHandler> WS_CREATED = new CopyOnWriteArrayList<>();
    /** Message handlers per proxied socket WebProbe announced ("ws-open"). */
    static final Map<Long, List<burp.api.montoya.proxy.websocket.ProxyMessageHandler>> WS_PROXY_HANDLERS = new java.util.concurrent.ConcurrentHashMap<>();
    static final Map<Long, List<burp.api.montoya.websocket.MessageHandler>> WS_HANDLERS = new java.util.concurrent.ConcurrentHashMap<>();

    static int wsCount() { return WS_PROXY_CREATION.size() + WS_CREATED.size(); }

    static burp.api.montoya.websocket.WebSockets websockets() {
        return Api.obj()
                .on("registerWebSocketCreatedHandler", a -> reg(WS_CREATED, (burp.api.montoya.websocket.WebSocketCreatedHandler) a[0]))
                .as(burp.api.montoya.websocket.WebSockets.class);
    }

    /** "ws-open": WebProbe's proxy upgraded a WebSocket; the creation
     *  handlers may register message handlers on it. */
    static String wsOpen(int id, Map<String, Object> m) {
        long socket = (long) Wire.num(m.get("socket"));
        HttpRequest upgrade = Ui.pair(m).request();
        List<burp.api.montoya.proxy.websocket.ProxyMessageHandler> ph = new CopyOnWriteArrayList<>();
        List<burp.api.montoya.websocket.MessageHandler> mh = new CopyOnWriteArrayList<>();
        burp.api.montoya.proxy.websocket.ProxyWebSocket pws = Api.obj()
                .on("registerProxyMessageHandler", a -> Bridge.register(ph, (burp.api.montoya.proxy.websocket.ProxyMessageHandler) a[0]))
                .as(burp.api.montoya.proxy.websocket.ProxyWebSocket.class);
        burp.api.montoya.websocket.WebSocket ws = Api.obj()
                .on("registerMessageHandler", a -> Bridge.register(mh, (burp.api.montoya.websocket.MessageHandler) a[0]))
                .as(burp.api.montoya.websocket.WebSocket.class);
        for (var h : WS_PROXY_CREATION) {
            try {
                h.handleWebSocketCreation(Api.obj().on("proxyWebSocket", a -> pws).on("upgradeRequest", a -> upgrade)
                        .as(burp.api.montoya.proxy.websocket.ProxyWebSocketCreation.class));
            } catch (Throwable t) { Logs.error("[bridge] WebSocket creation handler failed: " + Logs.trace(t)); }
        }
        for (var h : WS_CREATED) {
            try {
                h.handleWebSocketCreated(Api.obj().on("webSocket", a -> ws).on("upgradeRequest", a -> upgrade).on("toolSource", a -> Messages.tool("Proxy"))
                        .as(burp.api.montoya.websocket.WebSocketCreated.class));
            } catch (Throwable t) { Logs.error("[bridge] WebSocket created handler failed: " + Logs.trace(t)); }
        }
        WS_PROXY_HANDLERS.put(socket, ph);
        WS_HANDLERS.put(socket, mh);
        return "{\"id\":" + id + ",\"handlers\":" + (ph.size() + mh.size()) + "}";
    }

    /** "ws-message": one data message of a watched socket at one stage.
     *  "received" (before interception): proxy "received" handlers, whose
     *  verdict may force or skip interception. "send" (after the user's
     *  edit): proxy "to be sent" handlers, then websockets() handlers. */
    static String wsMessage(int id, Map<String, Object> m) {
        long socket = (long) Wire.num(m.get("socket"));
        boolean binary = Boolean.TRUE.equals(m.get("binary"));
        boolean received = "received".equals(Wire.str(m, "stage", "received"));
        burp.api.montoya.websocket.Direction dir = Boolean.TRUE.equals(m.get("toServer"))
                ? burp.api.montoya.websocket.Direction.CLIENT_TO_SERVER : burp.api.montoya.websocket.Direction.SERVER_TO_CLIENT;
        byte[][] data = { Wire.unb64(Wire.str(m, "payload", "")) };
        String verdict = "CONTINUE";
        String drop = "{\"id\":" + id + ",\"verdict\":\"DROP\"}";
        for (var h : WS_PROXY_HANDLERS.getOrDefault(socket, List.of())) {
            Object r;
            try {
                if (received) r = binary ? h.handleBinaryMessageReceived(wsMsg(burp.api.montoya.proxy.websocket.InterceptedBinaryMessage.class, data[0], dir, true))
                                         : h.handleTextMessageReceived(wsMsg(burp.api.montoya.proxy.websocket.InterceptedTextMessage.class, data[0], dir, false));
                else r = binary ? h.handleBinaryMessageToBeSent(wsMsg(burp.api.montoya.proxy.websocket.InterceptedBinaryMessage.class, data[0], dir, true))
                                : h.handleTextMessageToBeSent(wsMsg(burp.api.montoya.proxy.websocket.InterceptedTextMessage.class, data[0], dir, false));
            } catch (Throwable t) { Logs.error("[bridge] WebSocket message handler failed: " + Logs.trace(t)); continue; }
            String k = wsApply(r, data);
            if (k.equals("DROP")) return drop;
            if (received && !k.equals("CONTINUE")) verdict = k;
        }
        if (!received) {
            for (var h : WS_HANDLERS.getOrDefault(socket, List.of())) {
                Object r;
                try { r = binary ? h.handleBinaryMessage(wsMsg(burp.api.montoya.websocket.BinaryMessage.class, data[0], dir, true))
                                 : h.handleTextMessage(wsMsg(burp.api.montoya.websocket.TextMessage.class, data[0], dir, false)); }
                catch (Throwable t) { Logs.error("[bridge] WebSocket message handler failed: " + Logs.trace(t)); continue; }
                if (wsApply(r, data).equals("DROP")) return drop;
            }
        }
        return "{\"id\":" + id + ",\"verdict\":\"" + verdict + "\",\"payload\":" + Wire.Json.esc(Wire.b64(data[0])) + "}";
    }

    static void wsClose(Map<String, Object> m) {
        long socket = (long) Wire.num(m.get("socket"));
        var ph = WS_PROXY_HANDLERS.remove(socket);
        var mh = WS_HANDLERS.remove(socket);
        if (ph != null) for (var h : ph) try { h.onClose(); } catch (Throwable t) { Logs.error("[bridge] onClose failed: " + Logs.trace(t)); }
        if (mh != null) for (var h : mh) try { h.onClose(); } catch (Throwable t) { Logs.error("[bridge] onClose failed: " + Logs.trace(t)); }
    }

    static <T> T wsMsg(Class<T> iface, byte[] payload, burp.api.montoya.websocket.Direction dir, boolean binary) {
        Object p = binary ? Messages.bytes(payload.clone()) : new String(payload, java.nio.charset.StandardCharsets.UTF_8);
        return Api.obj().on("payload", a -> p).on("direction", a -> dir)
                .on("annotations", a -> Messages.annotations("", HighlightColor.NONE)).as(iface);
    }

    /** A handler's action: its payload replaces the message; the verdict
     *  (CONTINUE, INTERCEPT, DO_NOT_INTERCEPT, DROP) is returned. */
    static String wsApply(Object action, byte[][] data) {
        if (action == null) return "CONTINUE";
        try {
            // Through the action's public interface (its class may not be accessible).
            Class<?> i = action.getClass().getInterfaces()[0];
            Object kind = i.getMethod("action").invoke(action);
            Object p = i.getMethod("payload").invoke(action);
            if (p instanceof String str) data[0] = str.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            else if (p instanceof ByteArray b) data[0] = b.getBytes();
            return kind == null ? "CONTINUE" : ((Enum<?>) kind).name();
        } catch (ReflectiveOperationException e) {
            return "CONTINUE";
        }
    }

    static burp.api.montoya.scope.Scope scope() {
        return Api.obj()
                .on("isInScope", a -> Boolean.TRUE.equals(Wire.call("scope.in", "{\"url\":" + Wire.Json.esc(String.valueOf(a[0])) + "}")))
                .on("includeInScope", a -> { Wire.call("scope.include", "{\"url\":" + Wire.Json.esc(String.valueOf(a[0])) + "}"); scopeChanged(); return null; })
                .on("excludeFromScope", a -> { Wire.call("scope.exclude", "{\"url\":" + Wire.Json.esc(String.valueOf(a[0])) + "}"); scopeChanged(); return null; })
                .on("registerScopeChangeHandler", a -> Bridge.register(SCOPE_HANDLERS, a[0]))
                .as(burp.api.montoya.scope.Scope.class);
    }

    /** Scope change handlers hear changes made through the API (changes in
     *  WebProbe's own Target scope editor are not reported yet). */
    static void scopeChanged() {
        Object ev = Api.obj().as(burp.api.montoya.scope.ScopeChange.class);
        for (Object h : SCOPE_HANDLERS) ((burp.api.montoya.scope.ScopeChangeHandler) h).scopeChanged((burp.api.montoya.scope.ScopeChange) ev);
    }

    static burp.api.montoya.sitemap.SiteMap siteMap() {
        return Api.obj()
                .on("requestResponses", 0, a -> pairs(Wire.call("sitemap.items", null)))
                .on("requestResponses", 1, a -> {
                    List<HttpRequestResponse> out = new ArrayList<>();
                    for (HttpRequestResponse rr : pairs(Wire.call("sitemap.items", null))) if (((burp.api.montoya.sitemap.SiteMapFilter) a[0]).matches(node(rr))) out.add(rr);
                    return out;
                })
                .on("issues", 0, a -> issues())
                .on("issues", 1, a -> {
                    List<AuditIssue> out = new ArrayList<>();
                    for (AuditIssue i : issues()) if (((burp.api.montoya.sitemap.SiteMapFilter) a[0]).matches(node(i.baseUrl()))) out.add(i);
                    return out;
                })
                .on("add", a -> {
                    if (a[0] instanceof AuditIssue i) Wire.call("scanner.add-issues", "{\"issues\":[" + issueJson(i) + "]}");
                    else { HttpRequestResponse rr = (HttpRequestResponse) a[0]; Wire.call("sitemap.add", msg(rr.request(), rr.response())); }
                    return null;
                })
                .as(burp.api.montoya.sitemap.SiteMap.class);
    }

    static burp.api.montoya.sitemap.SiteMapNode node(HttpRequestResponse rr) { return node(rr.request().url()); }

    static burp.api.montoya.sitemap.SiteMapNode node(String url) {
        return Api.obj().on("url", a -> url).as(burp.api.montoya.sitemap.SiteMapNode.class);
    }

    @SuppressWarnings("unchecked")
    static List<AuditIssue> issues() {
        List<AuditIssue> out = new ArrayList<>();
        Object r = Wire.call("scanner.issues", null);
        if (r instanceof List<?> l) {
            for (Object o : l) {
                Map<String, Object> m = (Map<String, Object>) o;
                out.add(issue(Wire.str(m, "name", ""), Wire.str(m, "detail", ""), "", Wire.str(m, "baseUrl", ""),
                        severity(Wire.str(m, "severity", "info")), confidence(Wire.str(m, "confidence", "Firm")), List.of()));
            }
        }
        return out;
    }

    static AuditIssueSeverity severity(String s) {
        return switch (s.toLowerCase()) { case "high" -> AuditIssueSeverity.HIGH; case "medium" -> AuditIssueSeverity.MEDIUM; case "low" -> AuditIssueSeverity.LOW; default -> AuditIssueSeverity.INFORMATION; };
    }

    static AuditIssueConfidence confidence(String s) {
        return switch (s.toLowerCase()) { case "certain" -> AuditIssueConfidence.CERTAIN; case "tentative" -> AuditIssueConfidence.TENTATIVE; default -> AuditIssueConfidence.FIRM; };
    }

    static burp.api.montoya.repeater.Repeater repeater() {
        return Api.obj()
                .on("sendToRepeater", a -> {
                    HttpRequest q = (HttpRequest) a[0];
                    String m = msg(q, null);
                    Wire.call("repeater.send", m.substring(0, m.length() - 1) + ",\"name\":" + Wire.Json.esc(a.length > 1 ? String.valueOf(a[1]) : "") + "}");
                    return null;
                })
                .as(burp.api.montoya.repeater.Repeater.class);
    }

    static burp.api.montoya.comparer.Comparer comparer() {
        return Api.obj().on("sendToComparer", a -> {
            Object[] items = a[0] instanceof Object[] arr ? arr : a;
            StringBuilder j = new StringBuilder("{\"items\":[");
            int k = 0;
            for (Object o : items) j.append(k++ > 0 ? "," : "").append(Wire.Json.esc(Wire.b64(((ByteArray) o).getBytes())));
            Wire.call("comparer.send", j.append("]}").toString());
            return null;
        }).as(burp.api.montoya.comparer.Comparer.class);
    }

    static burp.api.montoya.decoder.Decoder decoder() {
        return Api.obj().on("sendToDecoder", a -> {
            Wire.call("decoder.send", "{\"items\":[" + Wire.Json.esc(Wire.b64(((ByteArray) a[0]).getBytes())) + "]}");
            return null;
        }).as(burp.api.montoya.decoder.Decoder.class);
    }

    static burp.api.montoya.organizer.Organizer organizer() {
        return Api.obj()
                .on("sendToOrganizer", a -> {
                    if (a[0] instanceof HttpRequestResponse rr) Wire.call("organizer.send", msg(rr.request(), rr.response()));
                    else Wire.call("organizer.send", msg((HttpRequest) a[0], null));
                    return null;
                })
                .on("items", 0, a -> organizerItems())
                .on("items", 1, a -> filtered(organizerItems(), a[0], "matches"))
                .as(burp.api.montoya.organizer.Organizer.class);
    }

    @SuppressWarnings("unchecked")
    static List<Object> organizerItems() {
        List<Object> out = new ArrayList<>();
        Object r = Wire.call("organizer.items", null);
        if (r instanceof List<?> l) {
            for (Object o : l) {
                Map<String, Object> m = (Map<String, Object>) o;
                HttpRequestResponse rr = Ui.pair(m);
                out.add(Api.obj()
                        .on("id", a -> (int) Wire.num(m.get("id")))
                        // WebProbe's Organizer has no status column: every item is new.
                        .on("status", a -> burp.api.montoya.organizer.OrganizerItemStatus.NEW)
                        .on("request", a -> rr.request()).on("response", a -> rr.response()).on("hasResponse", a -> rr.response() != null)
                        .on("httpService", a -> rr.request().httpService()).on("url", a -> rr.request().url())
                        .on("annotations", a -> Messages.annotations(Wire.str(m, "notes", ""), HighlightColor.NONE))
                        .as(burp.api.montoya.organizer.OrganizerItem.class));
            }
        }
        return out;
    }

    static burp.api.montoya.http.sessions.CookieJar cookieJar() {
        return Api.obj()
                .on("cookies", a -> {
                    List<Object> out = new ArrayList<>();
                    Object r = Wire.call("cookiejar.cookies", null);
                    if (r instanceof List<?> l) {
                        for (Object o : l) {
                            @SuppressWarnings("unchecked") Map<String, Object> m = (Map<String, Object>) o;
                            out.add(Api.obj().on("name", x -> Wire.str(m, "name", "")).on("value", x -> Wire.str(m, "value", ""))
                                    .on("domain", x -> Wire.str(m, "domain", "")).on("path", x -> Wire.str(m, "path", "/"))
                                    .on("expiration", x -> m.get("expires") == null ? java.util.Optional.empty()
                                            : java.util.Optional.of(java.time.ZonedDateTime.ofInstant(java.time.Instant.ofEpochSecond((long) Wire.num(m.get("expires"))), java.time.ZoneOffset.UTC)))
                                    .as(burp.api.montoya.http.message.Cookie.class));
                        }
                    }
                    return out;
                })
                .on("setCookie", a -> {
                    Long exp = a[4] instanceof java.time.ZonedDateTime z ? z.toEpochSecond() : null;
                    Wire.call("cookiejar.set", "{\"name\":" + Wire.Json.esc((String) a[0]) + ",\"value\":" + Wire.Json.esc((String) a[1]) + ",\"domain\":"
                            + Wire.Json.esc((String) a[2]) + ",\"path\":" + Wire.Json.esc(a[3] == null ? "/" : (String) a[3]) + ",\"expires\":" + exp + "}");
                    return null;
                })
                .as(burp.api.montoya.http.sessions.CookieJar.class);
    }

    // ------------------------------------------------------------ intruder()

    static final List<burp.api.montoya.intruder.PayloadGeneratorProvider> GENERATORS = new CopyOnWriteArrayList<>();
    static final List<burp.api.montoya.intruder.PayloadProcessor> PROCESSORS = new CopyOnWriteArrayList<>();
    /** Most payloads one generator may hand to an attack. */
    static final int MAX_GENERATED = 100_000;

    static burp.api.montoya.intruder.Intruder intruder() {
        return Api.obj()
                .on("registerPayloadGeneratorProvider", a -> reg(GENERATORS, (burp.api.montoya.intruder.PayloadGeneratorProvider) a[0]))
                .on("registerPayloadProcessor", a -> reg(PROCESSORS, (burp.api.montoya.intruder.PayloadProcessor) a[0]))
                .on("sendToIntruder", a -> {
                    // (request[, tab name]) or (service, template[, tab name]).
                    if (a[0] instanceof HttpRequest q) {
                        String m = msg(q, null);
                        Wire.call("intruder.send", m);
                        return null;
                    }
                    HttpService svc = (HttpService) a[0];
                    burp.api.montoya.intruder.HttpRequestTemplate t = (burp.api.montoya.intruder.HttpRequestTemplate) a[1];
                    String m = msg((HttpRequest) Messages.request(marked(t), Messages.svcOf(svc), null, HttpRequest.class), null);
                    Wire.call("intruder.send", m);
                    return null;
                })
                .as(burp.api.montoya.intruder.Intruder.class);
    }

    /** A template's content with WebProbe's § markers around its positions. */
    static byte[] marked(burp.api.montoya.intruder.HttpRequestTemplate t) {
        byte[] c = t.content().getBytes();
        byte[] mark = "§".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        List<int[]> at = new ArrayList<>();
        for (burp.api.montoya.core.Range r : t.insertionPointOffsets()) at.add(new int[] { r.startIndexInclusive(), r.endIndexExclusive() });
        at.sort((x, y) -> Integer.compare(x[0], y[0]));
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        int pos = 0;
        for (int[] r : at) {
            int s = Math.max(pos, Math.min(r[0], c.length)), e = Math.max(s, Math.min(r[1], c.length));
            out.write(c, pos, s - pos);
            out.writeBytes(mark);
            out.write(c, s, e - s);
            out.writeBytes(mark);
            pos = e;
        }
        out.write(c, pos, c.length - pos);
        return out.toByteArray();
    }

    /** HttpRequestTemplate.httpRequestTemplate(content | request, offsets). */
    static burp.api.montoya.intruder.HttpRequestTemplate template(Object content, List<?> offsets) {
        ByteArray c = content instanceof HttpRequest q ? Messages.bytes(Messages.rawOf(q)) : (ByteArray) content;
        List<Object> ranges = new ArrayList<>(offsets);
        return Api.obj().on("content", a -> c).on("insertionPointOffsets", a -> ranges)
                .as(burp.api.montoya.intruder.HttpRequestTemplate.class);
    }

    static List<String> names(List<?> l) {
        List<String> out = new ArrayList<>();
        for (Object o : l) {
            try {
                out.add(o instanceof burp.api.montoya.intruder.PayloadGeneratorProvider g ? g.displayName()
                        : o instanceof burp.api.montoya.http.sessions.SessionHandlingAction s ? s.name()
                        : ((burp.api.montoya.intruder.PayloadProcessor) o).displayName());
            } catch (Throwable t) {
                out.add(o.getClass().getSimpleName());
            }
        }
        return out;
    }

    /** GeneratedPayload.payload(..) / end() (value null). */
    static burp.api.montoya.intruder.GeneratedPayload generated(ByteArray v) {
        return Api.obj().on("value", a -> v).as(burp.api.montoya.intruder.GeneratedPayload.class);
    }

    static burp.api.montoya.intruder.PayloadProcessingResult processed(ByteArray v, burp.api.montoya.intruder.PayloadProcessingAction act) {
        return Api.obj().on("processedPayload", a -> v).on("action", a -> act)
                .as(burp.api.montoya.intruder.PayloadProcessingResult.class);
    }

    /** "intruder-generate": the payloads of generator `provider` for an
     *  attack on `request` (with § markers), first position base `base`. */
    static String generate(int id, Map<String, Object> m) {
        String want = Wire.str(m, "provider", "");
        burp.api.montoya.intruder.PayloadGeneratorProvider p = null;
        for (burp.api.montoya.intruder.PayloadGeneratorProvider g : GENERATORS) if (want.equals(names(List.of(g)).get(0))) p = g;
        if (p == null) return "{\"id\":" + id + ",\"error\":" + Wire.Json.esc("No payload generator named " + want + " is registered") + "}";
        byte[] raw = Wire.unb64(Wire.str(m, "request", ""));
        Messages.Svc svc = new Messages.Svc(Wire.str(m, "host", ""), (int) Wire.num(m.get("port")), Boolean.TRUE.equals(m.get("secure")));
        burp.api.montoya.intruder.HttpRequestTemplate t = unmarked(raw);
        HttpService service = svc.host().isEmpty() ? null : Messages.service(svc);
        burp.api.montoya.intruder.AttackConfiguration cfg = Api.obj()
                .on("httpService", a -> java.util.Optional.ofNullable(service))
                .on("requestTemplate", a -> t)
                .as(burp.api.montoya.intruder.AttackConfiguration.class);
        ByteArray base = Messages.bytes(Wire.str(m, "base", "").getBytes(java.nio.charset.StandardCharsets.UTF_8));
        burp.api.montoya.intruder.IntruderInsertionPoint point = Api.obj().on("baseValue", a -> base)
                .as(burp.api.montoya.intruder.IntruderInsertionPoint.class);
        burp.api.montoya.intruder.PayloadGenerator gen = p.providePayloadGenerator(cfg);
        StringBuilder out = new StringBuilder("{\"id\":" + id + ",\"payloads\":[");
        for (int n = 0; n < MAX_GENERATED; n++) {
            burp.api.montoya.intruder.GeneratedPayload g = gen.generatePayloadFor(point);
            ByteArray v = g == null ? null : g.value();
            if (v == null) break;
            out.append(n > 0 ? "," : "").append(Wire.Json.esc(new String(v.getBytes(), java.nio.charset.StandardCharsets.UTF_8)));
        }
        return out.append("]}").toString();
    }

    /** "intruder-process": payloads through processor `processor` (base
     *  value `base`); skipped ones are left out. */
    @SuppressWarnings("unchecked")
    static String process(int id, Map<String, Object> m) {
        String want = Wire.str(m, "processor", "");
        burp.api.montoya.intruder.PayloadProcessor p = null;
        for (burp.api.montoya.intruder.PayloadProcessor x : PROCESSORS) if (want.equals(names(List.of(x)).get(0))) p = x;
        if (p == null) return "{\"id\":" + id + ",\"error\":" + Wire.Json.esc("No payload processor named " + want + " is registered") + "}";
        ByteArray base = Messages.bytes(Wire.str(m, "base", "").getBytes(java.nio.charset.StandardCharsets.UTF_8));
        burp.api.montoya.intruder.IntruderInsertionPoint point = Api.obj().on("baseValue", a -> base)
                .as(burp.api.montoya.intruder.IntruderInsertionPoint.class);
        StringBuilder out = new StringBuilder("{\"id\":" + id + ",\"payloads\":[");
        int n = 0;
        for (Object o : (List<Object>) m.getOrDefault("payloads", List.of())) {
            ByteArray v = Messages.bytes(String.valueOf(o).getBytes(java.nio.charset.StandardCharsets.UTF_8));
            var data = Api.obj().on("currentPayload", a -> v).on("originalPayload", a -> v).on("insertionPoint", a -> point)
                    .as(burp.api.montoya.intruder.PayloadData.class);
            var r = p.processPayload(data);
            if (r == null || r.action() == burp.api.montoya.intruder.PayloadProcessingAction.SKIP_PAYLOAD) continue;
            ByteArray done = r.processedPayload() == null ? v : r.processedPayload();
            out.append(n++ > 0 ? "," : "").append(Wire.Json.esc(new String(done.getBytes(), java.nio.charset.StandardCharsets.UTF_8)));
        }
        return out.append("]}").toString();
    }

    /** The template of a request with § markers: markers removed, their
     *  spans as insertion point offsets. */
    static burp.api.montoya.intruder.HttpRequestTemplate unmarked(byte[] raw) {
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        List<Object> ranges = new ArrayList<>();
        int open = -1;
        for (int i = 0; i < raw.length; i++) {
            if ((raw[i] & 0xff) == 0xc2 && i + 1 < raw.length && (raw[i + 1] & 0xff) == 0xa7) {
                if (open < 0) open = out.size(); else { ranges.add(Ui.range(open, out.size())); open = -1; }
                i++;
                continue;
            }
            out.write(raw[i]);
        }
        return template(Messages.bytes(out.toByteArray()), ranges);
    }

    // ------------------------------------------------------------ session handling actions

    static final List<burp.api.montoya.http.sessions.SessionHandlingAction> SESSION_ACTIONS = new CopyOnWriteArrayList<>();

    /** "session-action": a session rule invokes action `name` on a request. */
    static String sessionAction(int id, Map<String, Object> m) {
        String want = Wire.str(m, "name", "");
        for (var a : SESSION_ACTIONS) {
            if (!want.equals(names(List.of(a)).get(0))) continue;
            HttpRequest req = Ui.pair(m).request();
            var data = Api.obj().on("request", x -> req).on("macroRequestResponses", x -> List.of())
                    .on("annotations", x -> Messages.annotations("", HighlightColor.NONE))
                    .as(burp.api.montoya.http.sessions.SessionHandlingActionData.class);
            var r = a.performAction(data);
            HttpRequest out = r == null || r.request() == null ? req : r.request();
            return "{\"id\":" + id + ",\"request\":" + Wire.Json.esc(Wire.b64(Messages.rawOf(out))) + "}";
        }
        return "{\"id\":" + id + ",\"error\":" + Wire.Json.esc("No session handling action named " + want + " is registered") + "}";
    }

    // ------------------------------------------------------------ scanner()

    record Active(ActiveScanCheck check, ScanCheckType type) {}
    static final List<Active> ACTIVE = new CopyOnWriteArrayList<>();
    static final List<PassiveScanCheck> PASSIVE = new CopyOnWriteArrayList<>();
    static final List<ScanCheck> LEGACY = new CopyOnWriteArrayList<>();
    static final List<AuditInsertionPointProvider> POINT_PROVIDERS = new CopyOnWriteArrayList<>();

    static void scannerApi(Api.Obj o) {
        o.on("registerActiveScanCheck", a -> reg(ACTIVE, new Active((ActiveScanCheck) a[0], (ScanCheckType) a[1])))
         .on("registerPassiveScanCheck", a -> reg(PASSIVE, (PassiveScanCheck) a[0]))
         .on("registerScanCheck", a -> reg(LEGACY, (ScanCheck) a[0]))
         .on("registerInsertionPointProvider", a -> reg(POINT_PROVIDERS, (AuditInsertionPointProvider) a[0]));
    }

    static <T> Object reg(List<T> l, T item) {
        Object r = Bridge.register(l, item);
        Ui.pushState();
        return r;
    }

    static int activeCount() { return ACTIVE.size() + LEGACY.size(); }
    static int passiveCount() { return PASSIVE.size() + LEGACY.size(); }

    /** AuditIssue.auditIssue(..) (and issues read back from WebProbe). */
    static AuditIssue issue(String name, String detail, String remediation, String baseUrl, AuditIssueSeverity sev, AuditIssueConfidence conf, List<HttpRequestResponse> rrs) {
        return Api.obj()
                .on("name", a -> name).on("detail", a -> detail).on("remediation", a -> remediation).on("baseUrl", a -> baseUrl)
                .on("httpService", a -> Messages.service(Messages.svcFromUrl(baseUrl)))
                .on("severity", a -> sev).on("confidence", a -> conf)
                .on("requestResponses", a -> rrs).on("collaboratorInteractions", a -> List.of())
                .text(name + " @ " + baseUrl)
                .as(AuditIssue.class);
    }

    @SuppressWarnings("unchecked")
    static AuditIssue issueFromFactory(Object[] a) {
        List<HttpRequestResponse> rrs = new ArrayList<>();
        if (a.length > 9) for (Object o : Messages.many(new Object[] { a[9] })) if (o instanceof HttpRequestResponse rr) rrs.add(rr);
        return issue((String) a[0], (String) a[1], (String) a[2], (String) a[3], (AuditIssueSeverity) a[4], (AuditIssueConfidence) a[5], rrs);
    }

    static String issueJson(AuditIssue i) {
        StringBuilder b = new StringBuilder("{\"name\":").append(Wire.Json.esc(i.name()))
                .append(",\"detail\":").append(Wire.Json.esc(i.detail() == null ? "" : i.detail()))
                .append(",\"remediation\":").append(Wire.Json.esc(i.remediation() == null ? "" : i.remediation()))
                .append(",\"baseUrl\":").append(Wire.Json.esc(i.baseUrl() == null ? "" : i.baseUrl()))
                .append(",\"severity\":").append(Wire.Json.esc(String.valueOf(i.severity())))
                .append(",\"confidence\":").append(Wire.Json.esc(String.valueOf(i.confidence())))
                .append(",\"evidence\":[");
        List<HttpRequestResponse> rrs = i.requestResponses() == null ? List.of() : i.requestResponses();
        for (int k = 0; k < rrs.size(); k++) b.append(k > 0 ? "," : "").append(msg(rrs.get(k).request(), rrs.get(k).response()));
        return b.append("]}").toString();
    }

    /** The Http a scan check gets: its requests go through the running
     *  scan's send path (stop, pause, progress, stored-input detection). */
    static burp.api.montoya.http.Http scanHttp() {
        return Api.obj()
                .on("sendRequest", a -> {
                    HttpRequest q = (HttpRequest) a[0];
                    Object r = Wire.call("scan-send", msg(q, null));
                    HttpResponse resp = r instanceof String s && !s.isEmpty() ? (HttpResponse) Messages.response(Wire.unb64(s), null, HttpResponse.class) : null;
                    return Messages.requestResponse(q, resp, Messages.annotations("", HighlightColor.NONE));
                })
                .as(burp.api.montoya.http.Http.class);
    }

    /** One of WebProbe's insertion points: payloads are placed (and
     *  encoded) by WebProbe. */
    static AuditInsertionPoint hostPoint(int index, String name, String base, HttpService svc) {
        return Api.obj()
                .on("name", a -> name)
                .on("baseValue", a -> base)
                .on("buildHttpRequestWithPayload", a -> {
                    Object r = Wire.call("scan-build", "{\"point\":" + index + ",\"payload\":" + Wire.Json.esc(Wire.b64(((ByteArray) a[0]).getBytes())) + "}");
                    return Messages.request(Wire.unb64(String.valueOf(r)), Messages.svcOf(svc), null, HttpRequest.class);
                })
                .on("issueHighlights", a -> List.of())
                .on("type", a -> burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPointType.EXTENSION_PROVIDED)
                .text(name)
                .as(AuditInsertionPoint.class);
    }

    /** AuditInsertionPoint.auditInsertionPoint(name, request, start, end). */
    static AuditInsertionPoint rangePoint(String name, HttpRequest req, int start, int end) {
        byte[] raw = Messages.rawOf(req);
        String base = new String(raw, start, end - start, Messages.L1);
        return Api.obj()
                .on("name", a -> name)
                .on("baseValue", a -> base)
                .on("buildHttpRequestWithPayload", a -> {
                    byte[] p = ((ByteArray) a[0]).getBytes();
                    byte[] out = new byte[raw.length - (end - start) + p.length];
                    System.arraycopy(raw, 0, out, 0, start);
                    System.arraycopy(p, 0, out, start, p.length);
                    System.arraycopy(raw, end, out, start + p.length, raw.length - end);
                    return Messages.request(out, Messages.svcOf(req.httpService()), null, HttpRequest.class);
                })
                .on("issueHighlights", a -> List.of(Ui.range(start, start + ((ByteArray) a[0]).length())))
                .on("type", a -> burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPointType.EXTENSION_PROVIDED)
                .as(AuditInsertionPoint.class);
    }

    private static void collect(AuditResult r, List<String> out) {
        if (r == null || r.auditIssues() == null) return;
        for (AuditIssue i : r.auditIssues()) out.add(issueJson(i));
    }

    /** WebProbe's active scan reached the extension checks for one request. */
    @SuppressWarnings("unchecked")
    static String scanActive(int id, Map<String, Object> m) {
        HttpRequestResponse base = Ui.pair(m);
        List<AuditInsertionPoint> points = new ArrayList<>();
        Object ps = m.get("points");
        if (ps instanceof List<?> l) {
            int k = 0;
            for (Object o : l) {
                Map<String, Object> p = (Map<String, Object>) o;
                points.add(hostPoint(k++, Wire.str(p, "name", ""), Wire.str(p, "base", ""), base.request().httpService()));
            }
        }
        for (AuditInsertionPointProvider p : POINT_PROVIDERS) {
            try { List<AuditInsertionPoint> more = p.provideInsertionPoints(base); if (more != null) points.addAll(more); }
            catch (Throwable t) { Logs.error("[bridge] insertion point provider failed: " + Logs.trace(t)); }
        }
        List<String> issues = new ArrayList<>();
        burp.api.montoya.http.Http http = scanHttp();
        AuditInsertionPoint whole = points.isEmpty() ? null : points.get(0);
        for (Active a : ACTIVE) {
            try {
                if (a.type() == ScanCheckType.PER_INSERTION_POINT) { for (AuditInsertionPoint p : points) collect(a.check().doCheck(base, p, http), issues); }
                else if (whole != null) collect(a.check().doCheck(base, whole, http), issues);
            } catch (Throwable t) { Logs.error("[bridge] active scan check " + a.check().checkName() + " failed: " + Logs.trace(t)); }
        }
        for (ScanCheck c : LEGACY) {
            try { for (AuditInsertionPoint p : points) collect(c.activeAudit(base, p), issues); }
            catch (Throwable t) { Logs.error("[bridge] scan check failed: " + Logs.trace(t)); }
        }
        return "{\"id\":" + id + ",\"issues\":[" + String.join(",", issues) + "]}";
    }

    static String scanPassive(int id, Map<String, Object> m) {
        HttpRequestResponse base = Ui.pair(m);
        List<String> issues = new ArrayList<>();
        for (PassiveScanCheck c : PASSIVE) {
            try { collect(c.doCheck(base), issues); } catch (Throwable t) { Logs.error("[bridge] passive scan check " + c.checkName() + " failed: " + Logs.trace(t)); }
        }
        for (ScanCheck c : LEGACY) {
            try { collect(c.passiveAudit(base), issues); } catch (Throwable t) { Logs.error("[bridge] scan check failed: " + Logs.trace(t)); }
        }
        return "{\"id\":" + id + ",\"issues\":[" + String.join(",", issues) + "]}";
    }

    // ------------------------------------------------------------ collaborator()

    /** Payload ids per client secret key (this JVM's lifetime). */
    static final Map<String, List<String>> CLIENT_IDS = new java.util.concurrent.ConcurrentHashMap<>();

    static burp.api.montoya.collaborator.Collaborator collaborator() {
        return Api.obj()
                .on("createClient", a -> client(java.util.UUID.randomUUID().toString()))
                .on("restoreClient", a -> client(String.valueOf(a[0])))
                .on("defaultPayloadGenerator", a -> {
                    Api.Obj o = Api.obj();
                    o.on("generatePayload", x -> payload(null, x));
                    return o.as(burp.api.montoya.collaborator.CollaboratorPayloadGenerator.class);
                })
                .as(burp.api.montoya.collaborator.Collaborator.class);
    }

    static Object server(String domain) {
        return Api.obj().on("address", a -> domain).on("isLiteralAddress", a -> domain.matches("[0-9.]+")).text(domain)
                .as(burp.api.montoya.collaborator.CollaboratorServer.class);
    }

    @SuppressWarnings("unchecked")
    static Object payload(String key, Object[] a) {
        if (a.length > 0 && a[0] instanceof String) throw Api.unsupported("CollaboratorClient", "generatePayload(customData)");
        Map<String, Object> r = (Map<String, Object>) Wire.call("collab.payload", null);
        String id = Wire.str(r, "id", ""), full = Wire.str(r, "payload", ""), domain = Wire.str(r, "server", "");
        if (key != null) CLIENT_IDS.computeIfAbsent(key, k -> new CopyOnWriteArrayList<>()).add(id);
        boolean bare = false;
        for (Object o : Messages.many(a.length == 0 ? new Object[0] : new Object[] { a[a.length - 1] })) if (String.valueOf(o).equals("WITHOUT_SERVER_LOCATION")) bare = true;
        String text = bare ? full.split("\\.")[0] : full;
        java.util.Optional<Object> payloadServer = bare ? java.util.Optional.empty() : java.util.Optional.of(server(domain));
        Object idObj = Api.obj().text(id).as(burp.api.montoya.collaborator.InteractionId.class);
        return Api.obj()
                .on("id", x -> idObj)
                .on("customData", x -> java.util.Optional.empty())
                .on("server", x -> payloadServer)
                .text(text)
                .as(burp.api.montoya.collaborator.CollaboratorPayload.class);
    }

    @SuppressWarnings("unchecked")
    static List<Object> interactions(String key) {
        List<Object> out = new ArrayList<>();
        StringBuilder arr = new StringBuilder("[");
        for (String id : CLIENT_IDS.getOrDefault(key, List.of())) arr.append(arr.length() > 1 ? "," : "").append(Wire.Json.esc(id));
        Object r = Wire.call("collab.interactions", "{\"ids\":" + arr + "]}");
        if (r instanceof List<?> l) for (Object o : l) out.add(interaction((Map<String, Object>) o));
        return out;
    }

    static Object interaction(Map<String, Object> m) {
        String type = Wire.str(m, "type", "DNS");
        Object idObj = Api.obj().text(Wire.str(m, "token", "")).as(burp.api.montoya.collaborator.InteractionId.class);
        java.time.ZonedDateTime at = java.time.ZonedDateTime.ofInstant(java.time.Instant.ofEpochSecond((long) Wire.num(m.get("time"))), java.time.ZoneOffset.UTC);
        String client = Wire.str(m, "client", "0.0.0.0");
        String ip = client.contains(":") && client.indexOf(':') == client.lastIndexOf(':') ? client.substring(0, client.indexOf(':')) : client;
        Object dns = !type.equals("DNS") ? null : Api.obj()
                .on("queryType", a -> dnsType((int) Wire.num(m.get("qtype"))))
                .on("query", a -> Messages.bytes(Wire.unb64(Wire.str(m, "query", ""))))
                .as(burp.api.montoya.collaborator.DnsDetails.class);
        Object http = !type.equals("HTTP") ? null : Api.obj()
                .on("protocol", a -> burp.api.montoya.http.HttpProtocol.HTTP)
                .on("requestResponse", a -> Messages.requestResponse((HttpRequest) Messages.request(Wire.unb64(Wire.str(m, "request", "")), new Messages.Svc("", 80, false), null, HttpRequest.class), null, Messages.annotations("", HighlightColor.NONE)))
                .as(burp.api.montoya.collaborator.HttpDetails.class);
        Object smtp = !type.equals("SMTP") ? null : Api.obj()
                .on("protocol", a -> burp.api.montoya.collaborator.SmtpProtocol.SMTP)
                .on("conversation", a -> Wire.str(m, "conversation", ""))
                .as(burp.api.montoya.collaborator.SmtpDetails.class);
        return Api.obj()
                .on("id", a -> idObj)
                .on("type", a -> burp.api.montoya.collaborator.InteractionType.valueOf(type))
                .on("timeStamp", a -> at)
                .on("clientIp", a -> java.net.InetAddress.getByName(ip))
                .on("clientPort", a -> 0)
                .on("dnsDetails", a -> java.util.Optional.ofNullable(dns))
                .on("httpDetails", a -> java.util.Optional.ofNullable(http))
                .on("smtpDetails", a -> java.util.Optional.ofNullable(smtp))
                .on("customData", a -> java.util.Optional.empty())
                .as(burp.api.montoya.collaborator.Interaction.class);
    }

    static Object dnsType(int q) {
        String n = switch (q) { case 1 -> "A"; case 28 -> "AAAA"; case 5 -> "CNAME"; case 15 -> "MX"; case 16 -> "TXT"; case 2 -> "NS"; case 6 -> "SOA"; case 12 -> "PTR"; case 33 -> "SRV"; default -> "A"; };
        try { return Enum.valueOf(burp.api.montoya.collaborator.DnsQueryType.class, n); } catch (Exception e) { return burp.api.montoya.collaborator.DnsQueryType.values()[0]; }
    }

    static Object client(String key) {
        Object secret = Api.obj().text(key).as(burp.api.montoya.collaborator.SecretKey.class);
        return Api.obj()
                .on("generatePayload", a -> payload(key, a))
                .on("getAllInteractions", a -> interactions(key))
                .on("getInteractions", a -> {
                    List<Object> out = new ArrayList<>();
                    burp.api.montoya.collaborator.InteractionFilter f = (burp.api.montoya.collaborator.InteractionFilter) a[0];
                    for (Object i : interactions(key)) if (f.matches(null, (burp.api.montoya.collaborator.Interaction) i)) out.add(i);
                    return out;
                })
                .on("server", a -> {
                    @SuppressWarnings("unchecked") Map<String, Object> r = (Map<String, Object>) Wire.call("collab.payload", null);
                    return server(Wire.str(r, "server", ""));
                })
                .on("getSecretKey", a -> secret)
                .as(burp.api.montoya.collaborator.CollaboratorClient.class);
    }
}
