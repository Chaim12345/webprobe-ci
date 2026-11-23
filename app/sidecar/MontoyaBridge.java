// MontoyaBridge.java: the sidecar JVM that runs a Burp Montoya extension
// (.jar) for WebProbe. The Montoya API classes come from the jar WebProbe's
// resource resolver finds (montoya-api or burpsuite.jar); the bridge itself
// is several source files in one directory. WebProbe compiles them once per
// version (the JDK's javac) and runs the classes:
//
//   java -cp montoya-api.jar:CLASSES MontoyaBridge [--startup] [--data FILE]
//        [--prefs DIR] <ext.jar>
//
// (Java's multi-file source launcher, `java -cp montoya-api.jar
// MontoyaBridge.java ...`, runs them too, compiling on every start.)
//
// --startup: loaded with WebProbe (its window opens on demand only);
// --data: the extension's saved extensionData() (JSON) from the project;
// --prefs: where preferences() files live.
//
// Files: Api (proxy helper, Unsupported), Wire (protocol), Logs (logging()),
// Messages (HTTP value types), Factory (MontoyaObjectFactory), Bridge
// (MontoyaApi, extension(), burpSuite(), http(), proxy()), Ui
// (userInterface()), Persist (persistence()), Utils (utilities()).
//
// Protocol: one JSON object per line. Messages travel as Base64 bytes.
//   -> {"type":"ping"}                         <= {"type":"pong","name":..,"handlers":{..}}
//   -> {"type":"request","id":N,"raw":b64,"host","port","secure","tool",
//       "notes","highlight"}
//   <= {"id":N,"action":"continue"|"drop","raw":b64 (only when edited),
//       "notes","highlight"}
//   -> {"type":"response","id":N,"raw":b64,"request":b64,...same}
//   <= same as for a request
//   <= {"type":"send","sid":K,"raw":b64,"host","port","secure"}   (Http.sendRequest)
//   -> {"type":"sent","sid":K,"raw":b64}  or  {"type":"sent","sid":K,"error":".."}
//   <= {"type":"event","level":"info"|..,"message":..}             (raise*Event)
//   -> {"type":"shutdown"}  (unloading handlers run, bridge exits 0)
//   <= {"type":"ui","tabs":[..],"headless","visible","menus","requestEditors","responseEditors"}
//   <= {"type":"persist","data":{..}}                 (extensionData() changed)
//   -> {"type":"show"}                                (open / raise the window)
//   -> {"type":"restore","data":{..}}                 (a project was loaded)
//   -> {"type":"menu","id":N,"tool","invocation","messages":[{request,response,host,port,secure}],
//       "editor":{"context","start","end","caret"}}   <= {"id":N,"items":[{"id","label"}]}
//   -> {"type":"menu-invoke","id":N,"item":id}         <= {"id":N,"ok","request"?,"response"?}
//   -> {"type":"editors","id":N,request,response,host,port,secure,tool}
//                                                      <= {"id":N,"editors":[{"caption","enabled","request"}]}
//   -> {"type":"editor-get","id":N}                    <= {"id":N,"request"?}
//
// Handler order follows Burp: for a request the Proxy's
// handleRequestReceived, its handleRequestToBeSent, then every HTTP
// handler's handleHttpRequestToBeSent; for a response the HTTP handlers'
// handleHttpResponseReceived, then the Proxy's handleResponseReceived and
// handleResponseToBeSent. Each sees the previous one's edits.

import burp.api.montoya.BurpExtension;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.internal.ObjectFactoryLocator;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.InterceptedResponse;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyResponseHandler;

import java.io.File;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import java.util.ServiceLoader;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

public class MontoyaBridge {

    public static void main(String[] args) throws Exception {
        Wire.start();
        String jar = null;
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--startup": Ui.startup = true; break;
                case "--data": {
                    String text = java.nio.file.Files.readString(java.nio.file.Path.of(args[++i]), StandardCharsets.UTF_8);
                    @SuppressWarnings("unchecked")
                    Map<String, Object> data = (Map<String, Object>) Wire.Json.parse(text);
                    Persist.fromJson(Persist.ROOT, data);
                    break;
                }
                case "--prefs": Persist.prefsDir = java.nio.file.Path.of(args[++i]); break;
                default: jar = args[i];
            }
        }
        if (jar == null) {
            Logs.error("usage: java -cp montoya-api.jar MontoyaBridge.java [--startup] [--data FILE] [--prefs DIR] <ext.jar>");
            System.exit(2);
        }
        Persist.ROOT.onChange = () -> Wire.send("{\"type\":\"persist\",\"data\":" + Persist.toJson(Persist.ROOT) + "}");
        Bridge.jarPath = new File(jar).getAbsolutePath();
        ObjectFactoryLocator.FACTORY = Factory.create();
        List<BurpExtension> exts = discover(jar);
        if (exts.isEmpty()) {
            Logs.error("[bridge] no burp.api.montoya.BurpExtension implementation found in " + jar);
            System.exit(2);
        }
        for (BurpExtension ext : exts) {
            Logs.output("[bridge] initializing " + ext.getClass().getName());
            try {
                ext.initialize(Bridge.api());
            } catch (Throwable t) {
                Logs.error("[bridge] the extension's initialize() failed: " + Logs.trace(t));
                Wire.out.flush();
                System.exit(3);
            }
        }
        Logs.output("[bridge] ready: " + Bridge.HTTP_HANDLERS.size() + " HTTP handler(s), " + Bridge.PROXY_REQUEST.size()
                + " proxy request handler(s), " + Bridge.PROXY_RESPONSE.size() + " proxy response handler(s)");
        while (true) {
            Map<String, Object> msg = Wire.INBOX.take();
            String type = Wire.str(msg, "type", "");
            if (type.equals("shutdown")) break;
            if (type.equals("show")) { Ui.show(); continue; }
            if (type.equals("ws-close")) { Engine.wsClose(msg); continue; }
            if (type.equals("restore")) {
                @SuppressWarnings("unchecked")
                Map<String, Object> data = (Map<String, Object>) msg.get("data");
                Persist.fromJson(Persist.ROOT, data);
                continue;
            }
            int mid = (int) Wire.num(msg.get("id"));
            try {
                switch (type) {
                    case "menu": Wire.send(Ui.menu(mid, msg)); continue;
                    case "menu-invoke": Wire.send(Ui.invoke(mid, Wire.str(msg, "item", ""))); continue;
                    case "editors": Wire.send(Ui.editors(mid, msg)); continue;
                    case "editor-get": Wire.send(Ui.edited(mid)); continue;
                    case "scan-active": Wire.send(Engine.scanActive(mid, msg)); continue;
                    case "scan-passive": Wire.send(Engine.scanPassive(mid, msg)); continue;
                    case "intruder-generate": Wire.send(Engine.generate(mid, msg)); continue;
                    case "intruder-process": Wire.send(Engine.process(mid, msg)); continue;
                    case "ws-open": Wire.send(Engine.wsOpen(mid, msg)); continue;
                    case "session-action": Wire.send(Engine.sessionAction(mid, msg)); continue;
                    case "ws-message": Wire.send(Engine.wsMessage(mid, msg)); continue;
                    default: break;
                }
            } catch (Throwable t) {
                Logs.error("[bridge] " + type + " failed: " + Logs.trace(t));
                Wire.send("{\"id\":" + mid + ",\"error\":" + Wire.Json.esc(String.valueOf(t)) + "}");
                continue;
            }
            if (type.equals("ping")) {
                Ui.pushState();
                Wire.send("{\"type\":\"pong\",\"name\":" + Wire.Json.esc(Bridge.name) + ",\"httpHandlers\":" + Bridge.HTTP_HANDLERS.size()
                        + ",\"proxyHandlers\":" + (Bridge.PROXY_REQUEST.size() + Bridge.PROXY_RESPONSE.size()) + "}");
                continue;
            }
            if (type.equals("request") || type.equals("response")) Wire.send(exchange(msg, type.equals("request")));
        }
        Bridge.unloadHandlers();
        Ui.dispose();
        Wire.out.flush();
        System.exit(0);
    }

    /** The extension classes: those named in META-INF/services, else (as
     *  Burp does) every class of the jar that implements BurpExtension. */
    static List<BurpExtension> discover(String jar) throws Exception {
        URLClassLoader cl = new URLClassLoader(new URL[] { new File(jar).toURI().toURL() }, MontoyaBridge.class.getClassLoader());
        List<BurpExtension> out = new ArrayList<>();
        for (BurpExtension e : ServiceLoader.load(BurpExtension.class, cl)) out.add(e);
        if (!out.isEmpty()) return out;
        byte[] marker = "burp/api/montoya/BurpExtension".getBytes(StandardCharsets.ISO_8859_1);
        try (JarFile jf = new JarFile(jar)) {
            for (Enumeration<JarEntry> en = jf.entries(); en.hasMoreElements();) {
                JarEntry je = en.nextElement();
                String n = je.getName();
                if (!n.endsWith(".class") || n.startsWith("burp/api/montoya/") || n.contains("META-INF/")) continue;
                byte[] b = jf.getInputStream(je).readAllBytes();
                if (Messages.find(b, marker, true, 0, b.length) < 0) continue;
                Class<?> c = Class.forName(n.substring(0, n.length() - 6).replace('/', '.'), false, cl);
                if (BurpExtension.class.isAssignableFrom(c) && !c.isInterface() && !java.lang.reflect.Modifier.isAbstract(c.getModifiers())) {
                    out.add((BurpExtension) c.getDeclaredConstructor().newInstance());
                }
            }
        }
        return out;
    }

    static HighlightColor color(String name) {
        if (name == null || name.isEmpty()) return HighlightColor.NONE;
        try { return HighlightColor.valueOf(name.toUpperCase(java.util.Locale.ROOT)); } catch (Exception e) { return HighlightColor.NONE; }
    }

    /** Run every handler on one message and answer with the verdict. */
    static String exchange(Map<String, Object> msg, boolean isRequest) {
        int id = (int) Wire.num(msg.get("id"));
        Messages.Svc svc = new Messages.Svc(Wire.str(msg, "host", ""), (int) Wire.num(msg.get("port")), Boolean.TRUE.equals(msg.get("secure")));
        String tool = Wire.str(msg, "tool", "Proxy");
        byte[] original = Wire.unb64(Wire.str(msg, "raw", ""));
        byte[] initiating = isRequest ? null : Wire.unb64(Wire.str(msg, "request", ""));
        Annotations[] ann = { Messages.annotations(Wire.str(msg, "notes", ""), color(Wire.str(msg, "highlight", ""))) };
        byte[] raw = original;
        boolean drop = false;
        try {
            Bridge.setCurrent(ann[0]);
            if (isRequest) {
                boolean proxy = tool.equalsIgnoreCase("proxy");
                for (int pass = 0; proxy && pass < 2 && !drop; pass++) {
                    for (ProxyRequestHandler h : Bridge.PROXY_REQUEST) {
                        InterceptedRequest ir = (InterceptedRequest) Messages.request(raw, svc, extras(id, ann, tool, null), InterceptedRequest.class);
                        Object act = pass == 0 ? h.handleRequestReceived(ir) : h.handleRequestToBeSent(ir);
                        Verdict v = verdict(act, ann);
                        if (v.drop) { drop = true; break; }
                        if (v.raw != null) raw = v.raw;
                    }
                }
                for (HttpHandler h : drop ? List.<HttpHandler>of() : Bridge.HTTP_HANDLERS) {
                    HttpRequestToBeSent r = (HttpRequestToBeSent) Messages.request(raw, svc, extras(id, ann, tool, null), HttpRequestToBeSent.class);
                    Verdict v = verdict(h.handleHttpRequestToBeSent(r), ann);
                    if (v.drop) { drop = true; break; }
                    if (v.raw != null) raw = v.raw;
                }
            } else {
                HttpRequest init = (HttpRequest) Messages.request(initiating, svc, null, HttpRequest.class);
                for (HttpHandler h : Bridge.HTTP_HANDLERS) {
                    HttpResponseReceived r = (HttpResponseReceived) Messages.response(raw, extras(id, ann, tool, init), HttpResponseReceived.class);
                    Verdict v = verdict(h.handleHttpResponseReceived(r), ann);
                    if (v.raw != null) raw = v.raw;
                }
                boolean proxy = tool.equalsIgnoreCase("proxy");
                for (int pass = 0; proxy && pass < 2 && !drop; pass++) {
                    for (ProxyResponseHandler h : Bridge.PROXY_RESPONSE) {
                        InterceptedResponse ir = (InterceptedResponse) Messages.response(raw, extras(id, ann, tool, init), InterceptedResponse.class);
                        Object act = pass == 0 ? h.handleResponseReceived(ir) : h.handleResponseToBeSent(ir);
                        Verdict v = verdict(act, ann);
                        if (v.drop) { drop = true; break; }
                        if (v.raw != null) raw = v.raw;
                    }
                }
            }
        } catch (Throwable t) {
            // One failing handler must not end the bridge: report it and let
            // this message through unchanged.
            Logs.error("[bridge] handler failed on message " + id + ": " + Logs.trace(t));
            raw = original;
            drop = false;
        } finally {
            Bridge.setCurrent(null);
        }
        StringBuilder reply = new StringBuilder("{\"id\":" + id + ",\"action\":\"" + (drop ? "drop" : "continue") + "\"");
        if (!drop && !Arrays.equals(raw, original)) reply.append(",\"raw\":").append(Wire.Json.esc(Wire.b64(raw)));
        reply.append(",\"notes\":").append(Wire.Json.esc(ann[0].notes()));
        HighlightColor c = ann[0].highlightColor();
        reply.append(",\"highlight\":").append(c == null || c == HighlightColor.NONE ? "null" : Wire.Json.esc(c.name()));
        return reply.append('}').toString();
    }

    /** The subtype methods of a handler's message: id, annotations, tool,
     *  initiating request. */
    static Api.Obj extras(int id, Annotations[] ann, String tool, HttpRequest initiating) {
        Api.Obj o = Api.obj()
                .on("messageId", a -> id)
                .on("annotations", a -> ann[0])
                .on("toolSource", a -> Messages.tool(tool));
        if (initiating != null) {
            o.on("initiatingRequest", a -> initiating).on("request", a -> initiating);
        }
        return o;
    }

    record Verdict(boolean drop, byte[] raw) {}

    /** A handler result: drop, or the message to continue with; its
     *  annotations become the exchange's. */
    static Verdict verdict(Object act, Annotations[] ann) {
        if (act == null) return new Verdict(false, null);
        Object kind = call(act, "action");
        String k = kind instanceof Enum<?> e ? e.name() : "CONTINUE";
        Object a = call(act, "annotations");
        if (a instanceof Annotations an && an != ann[0]) {
            ann[0].setNotes(an.notes());
            ann[0].setHighlightColor(an.highlightColor());
        }
        if (k.equals("DROP")) return new Verdict(true, null);
        if (k.startsWith("SPOOF")) Api.unsupported("RequestToBeSentAction", "spoof");
        Object m = call(act, "request");
        if (m == null) m = call(act, "response");
        return new Verdict(false, m instanceof HttpRequest || m instanceof HttpResponse ? Messages.rawOf(m) : null);
    }

    private static Object call(Object o, String method) {
        try {
            Method m = findMethod(o.getClass(), method);
            return m == null ? null : m.invoke(o);
        } catch (java.lang.reflect.InvocationTargetException e) {
            if (e.getCause() instanceof UnsupportedOperationException) return null;
            throw new RuntimeException(e.getCause());
        } catch (Exception e) {
            return null;
        }
    }

    private static Method findMethod(Class<?> c, String name) {
        for (Class<?> i : c.getInterfaces()) {
            try { return i.getMethod(name); } catch (NoSuchMethodException ignored) { }
        }
        try { return c.getMethod(name); } catch (NoSuchMethodException e) { return null; }
    }
}
