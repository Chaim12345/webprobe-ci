// Factory.java: the MontoyaObjectFactory behind the API's static creators
// (HttpRequest.httpRequest(..), HttpHeader.httpHeader(..),
// RequestToBeSentAction.continueWith(..), ProxyRequestReceivedAction.drop(),
// Annotations.annotations(..) ...). Methods it does not know fail with the
// usual UnsupportedOperationException.

import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.internal.MontoyaObjectFactory;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

final class Factory {
    private Factory() {}

    static MontoyaObjectFactory create() {
        InvocationHandler h = (proxy, m, args) -> call(m, args == null ? new Object[0] : args);
        return (MontoyaObjectFactory) Proxy.newProxyInstance(Factory.class.getClassLoader(), new Class<?>[] { MontoyaObjectFactory.class }, h);
    }

    private static byte[] raw(Object o) {
        if (o instanceof ByteArray b) return b.getBytes();
        if (o instanceof byte[] b) return b;
        return String.valueOf(o).getBytes(Messages.L1);
    }

    private static Object call(Method m, Object[] a) {
        String n = m.getName();
        Class<?> ret = m.getReturnType();
        switch (n) {
            case "toString": return "WebProbe MontoyaObjectFactory";
            case "hashCode": return 0;
            case "equals": return false;
            case "httpHeader":
                if (a.length == 2) return Messages.header(new String(raw(a[0]), StandardCharsets.UTF_8), new String(raw(a[1]), StandardCharsets.UTF_8));
                return Messages.header(String.valueOf(a[0]));
            case "byteArray":
                if (a[0] instanceof int[] ints) {
                    byte[] b = new byte[ints.length];
                    for (int i = 0; i < b.length; i++) b[i] = (byte) ints[i];
                    return Messages.bytes(b);
                }
                return Messages.bytes(raw(a[0]));
            case "byteArrayOfLength": return Messages.bytes(new byte[((Number) a[0]).intValue()]);
            case "httpService":
                if (a.length == 1) return Messages.service(Messages.svcFromUrl(String.valueOf(a[0])));
                if (a.length == 2) {
                    boolean secure = (Boolean) a[1];
                    return Messages.service(new Messages.Svc(String.valueOf(a[0]), secure ? 443 : 80, secure));
                }
                return Messages.service(new Messages.Svc(String.valueOf(a[0]), ((Number) a[1]).intValue(), (Boolean) a[2]));
            case "httpRequest":
                if (a.length == 0) return Messages.request(new byte[0], new Messages.Svc("", 80, false), null, HttpRequest.class);
                if (a.length == 1) return Messages.request(raw(a[0]), new Messages.Svc("", 80, false), null, HttpRequest.class);
                return Messages.request(raw(a[1]), Messages.svcOf((HttpService) a[0]), null, HttpRequest.class);
            case "httpRequestFromUrl": {
                String url = String.valueOf(a[0]);
                Messages.Svc svc = Messages.svcFromUrl(url);
                int i = url.indexOf("://");
                int slash = url.indexOf('/', i < 0 ? 0 : i + 3);
                String path = slash < 0 ? "/" : url.substring(slash);
                String req = "GET " + path + " HTTP/1.1\r\nHost: " + hostHeader(svc) + "\r\n\r\n";
                return Messages.request(req.getBytes(Messages.L1), svc, null, HttpRequest.class);
            }
            case "httpResponse":
                return Messages.response(a.length == 0 ? new byte[0] : raw(a[0]), null, HttpResponse.class);
            case "httpRequestResponse":
                return Messages.requestResponse((HttpRequest) a[0], (HttpResponse) a[1], a.length > 2 ? (Annotations) a[2] : Messages.annotations("", HighlightColor.NONE));
            case "annotations": {
                String notes = "";
                HighlightColor c = HighlightColor.NONE;
                for (Object o : a) {
                    if (o instanceof HighlightColor hc) c = hc; else if (o != null) notes = String.valueOf(o);
                }
                return Messages.annotations(notes, c);
            }
            case "highlightColor": {
                // HighlightColor.highlightColor("Red"): by display name or constant name.
                String want = String.valueOf(a[0]).trim();
                for (HighlightColor c : HighlightColor.values()) {
                    if (c.name().equalsIgnoreCase(want) || c.displayName().equalsIgnoreCase(want)) return c;
                }
                return HighlightColor.NONE;
            }
            case "range": return Ui.range(((Number) a[0]).intValue(), ((Number) a[1]).intValue());
            case "selection":
                if (a.length == 1) return Ui.selection((ByteArray) a[0], 0, ((ByteArray) a[0]).length());
                if (a.length == 2) return Ui.selection(Messages.bytes(new byte[0]), ((Number) a[0]).intValue(), ((Number) a[1]).intValue());
                return Ui.selection((ByteArray) a[0], ((Number) a[1]).intValue(), ((Number) a[2]).intValue());
            case "parameter":
                return Messages.parameter(String.valueOf(a[0]), String.valueOf(a[1]), (burp.api.montoya.http.message.params.HttpParameterType) a[2]);
            case "auditIssue": return Engine.issueFromFactory(a);
            case "secretKey": return Api.obj().text(String.valueOf(a[0])).as(burp.api.montoya.collaborator.SecretKey.class);
            case "interactionIdFilter": case "interactionPayloadFilter": {
                String want = String.valueOf(a[0]);
                return Api.obj().on("matches", x -> {
                    String id = ((burp.api.montoya.collaborator.Interaction) x[1]).id().toString();
                    return want.equals(id) || want.startsWith(id + ".");
                }).as(burp.api.montoya.collaborator.InteractionFilter.class);
            }
            case "auditResult": {
                List<Object> issues = new ArrayList<>(Messages.many(a.length == 0 ? new Object[0] : new Object[] { a[0] }));
                return Api.obj().on("auditIssues", x -> issues).as(burp.api.montoya.scanner.AuditResult.class);
            }
            case "auditInsertionPoint": return Engine.rangePoint((String) a[0], (HttpRequest) a[1], ((Number) a[2]).intValue(), ((Number) a[3]).intValue());
            case "persistedObject": return Persist.object(new Persist.Store());
            case "payload":
                return Engine.generated(a[0] instanceof ByteArray b ? b : Messages.bytes(String.valueOf(a[0]).getBytes(java.nio.charset.StandardCharsets.UTF_8)));
            case "payloadEnd": return Engine.generated(null);
            case "menu": return Ui.menu(String.valueOf(a[0]), List.of());
            case "basicMenuItem": return Ui.basicMenuItem(String.valueOf(a[0]), null);
            case "actionResult": {
                Object req = a[0];
                Object ann = a.length > 1 ? a[1] : Messages.annotations("", HighlightColor.NONE);
                return Api.obj().on("request", x -> req).on("annotations", x -> ann).as(burp.api.montoya.http.sessions.ActionResult.class);
            }
            case "usePayload": return Engine.processed((ByteArray) a[0], burp.api.montoya.intruder.PayloadProcessingAction.USE_PAYLOAD);
            case "skipPayload": return Engine.processed(null, burp.api.montoya.intruder.PayloadProcessingAction.SKIP_PAYLOAD);
            case "payloadProcessingResult": return Engine.processed((ByteArray) a[0], (burp.api.montoya.intruder.PayloadProcessingAction) a[1]);
            case "httpRequestTemplate":
                if (a[1] instanceof List<?> offsets) return Engine.template(a[0], offsets);
                break;
            default:
                break;
        }
        if (n.startsWith("persisted") && n.endsWith("List")) return Persist.list();
        if (n.contains("TextMessage") || n.contains("BinaryMessage")) return wsAction(n, ret, a);
        if (ret.getSimpleName().endsWith("Action")) return action(n, ret, a);
        throw Api.unsupported("MontoyaObjectFactory", n);
    }

    private static String hostHeader(Messages.Svc s) {
        boolean dflt = s.port() == (s.secure() ? 443 : 80);
        return dflt ? s.host() : s.host() + ":" + s.port();
    }

    /** The verdict a factory method name or enum argument stands for. */
    private static String kind(String method, Object[] a) {
        for (Object o : a) if (o instanceof Enum<?> e) return e.name();
        String m = method.toLowerCase(Locale.ROOT);
        if (m.endsWith("drop")) return "DROP";
        if (m.endsWith("donotintercept")) return "DO_NOT_INTERCEPT";
        if (m.endsWith("followuserrules")) return "FOLLOW_USER_RULES";
        if (m.endsWith("intercept")) return "INTERCEPT";
        return "CONTINUE";
    }

    /** A handler result: verdict, message and annotations. */
    /** WebSocket message actions (continueWithTextMessage, dropInitial..,
     *  interceptInitialProxyTextMessage, textMessageAction(p, action) ..). */
    static Object wsAction(String method, Class<?> iface, Object[] a) {
        String kind = method.startsWith("drop") ? "DROP" : method.startsWith("doNotIntercept") ? "DO_NOT_INTERCEPT"
                : method.startsWith("intercept") ? "INTERCEPT" : "CONTINUE";
        for (Object o : a) if (o instanceof Enum<?> e) kind = e.name();
        Object payload = a.length == 0 || a[0] instanceof Enum<?> ? null : a[0];
        String k = kind;
        return Api.obj().on("action", x -> verdict(iface, k)).on("payload", x -> payload).text(kind + "(" + iface.getSimpleName() + ")").as(iface);
    }

    static Object action(String method, Class<?> iface, Object[] a) {
        String kind = kind(method, a);
        Object msg = null;
        Annotations ann = null;
        for (Object o : a) {
            if (o instanceof HttpRequest || o instanceof HttpResponse) { if (msg == null) msg = o; }
            else if (o instanceof Annotations an) ann = an;
        }
        Object message = msg;
        // An action made without annotations carries the exchange's own.
        Annotations annotations = ann != null ? ann : Bridge.currentAnnotations();
        return Api.obj()
                .on("action", x -> verdict(iface, kind))
                .on("request", x -> message instanceof HttpRequest ? message : null)
                .on("response", x -> message instanceof HttpResponse ? message : null)
                .on("annotations", x -> annotations)
                .text(kind + "(" + iface.getSimpleName() + ")")
                .as(iface);
    }

    /** The interface's verdict enum constant named `kind` (CONTINUE when
     *  the enum has no such constant, as with FOLLOW_USER_RULES in older
     *  APIs). */
    @SuppressWarnings({ "unchecked", "rawtypes" })
    private static Object verdict(Class<?> iface, String kind) {
        try {
            Class<?> e = iface.getMethod("action").getReturnType();
            if (!e.isEnum()) return null;
            for (Object c : e.getEnumConstants()) if (((Enum) c).name().equals(kind)) return c;
            if (kind.equals("SPOOF")) for (Object c : e.getEnumConstants()) if (((Enum) c).name().startsWith("SPOOF")) return c;
            return Enum.valueOf((Class) e, "CONTINUE");
        } catch (NoSuchMethodException ex) {
            return null;
        }
    }
}
