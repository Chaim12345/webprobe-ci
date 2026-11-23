// Bridge.java: the MontoyaApi the extension gets, and the state behind it
// (name, registered handlers, unloading handlers). Bridged so far (R-03
// stages 1-4): extension(), burpSuite(), logging(), http(), proxy() request
// and response handlers, userInterface() (Ui), persistence() (Persist) and
// utilities() (Utils). Every other accessor or method throws
// UnsupportedOperationException("<Interface>.<method> is not supported by
// WebProbe"), reported once on the extension's error output.

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.burpsuite.BurpSuite;
import burp.api.montoya.burpsuite.TaskExecutionEngine;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.BurpSuiteEdition;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.core.Version;
import burp.api.montoya.extension.Extension;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyResponseHandler;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

final class Bridge {
    private Bridge() {}

    static volatile String name = "";
    static String jarPath = "";
    static final List<ExtensionUnloadingHandler> UNLOADING = new CopyOnWriteArrayList<>();
    static final List<HttpHandler> HTTP_HANDLERS = new CopyOnWriteArrayList<>();
    static final List<ProxyRequestHandler> PROXY_REQUEST = new CopyOnWriteArrayList<>();
    static final List<ProxyResponseHandler> PROXY_RESPONSE = new CopyOnWriteArrayList<>();
    static volatile TaskExecutionEngine.TaskExecutionEngineState taskState = TaskExecutionEngine.TaskExecutionEngineState.RUNNING;

    /** The annotations of the exchange the current thread is handling. */
    private static final ThreadLocal<Annotations> CURRENT = new ThreadLocal<>();

    static Annotations currentAnnotations() {
        Annotations a = CURRENT.get();
        return a != null ? a : Messages.annotations("", HighlightColor.NONE);
    }

    static void setCurrent(Annotations a) { CURRENT.set(a); }

    static <T> Object register(List<T> list, T item) {
        list.add(item);
        return Api.registration(() -> list.remove(item));
    }

    static void unloadHandlers() {
        for (ExtensionUnloadingHandler h : UNLOADING) {
            try { h.extensionUnloaded(); } catch (Throwable t) { Logs.error("unloading handler failed: " + Logs.trace(t)); }
        }
    }

    // ------------------------------------------------------------ accessors

    static MontoyaApi api() {
        Extension extension = extension();
        BurpSuite suite = burpSuite();
        Http http = http();
        burp.api.montoya.ui.UserInterface ui = Ui.userInterface();
        burp.api.montoya.proxy.Proxy proxy = proxy();
        burp.api.montoya.logging.Logging logging = Logs.logging();
        return Api.obj()
                .on("extension", a -> extension)
                .on("burpSuite", a -> suite)
                .on("http", a -> http)
                .on("logging", a -> logging)
                .on("userInterface", a -> ui)
                .on("proxy", a -> proxy)
                .on("persistence", a -> Persist.persistence())
                .on("scope", a -> Engine.scope())
                .on("collaborator", a -> Engine.collaborator())
                .on("siteMap", a -> Engine.siteMap())
                .on("repeater", a -> Engine.repeater())
                .on("intruder", a -> Engine.intruder())
                .on("organizer", a -> Engine.organizer())
                .on("comparer", a -> Engine.comparer())
                .on("decoder", a -> Engine.decoder())
                .on("websockets", a -> Engine.websockets())
                // WebProbe has no Burp AI: extensions see it switched off.
                .on("ai", a -> Api.obj().on("isEnabled", x -> false).as(burp.api.montoya.ai.Ai.class))
                .on("scanner", a -> { Api.Obj o = Api.obj(); Engine.scannerApi(o); return o.as(burp.api.montoya.scanner.Scanner.class); })
                .on("utilities", a -> Utils.utilities())
                .text("WebProbe MontoyaApi")
                .as(MontoyaApi.class);
    }

    static Extension extension() {
        return Api.obj()
                .on("setName", a -> {
                    name = String.valueOf(a[0]);
                    if (Ui.frame != null) Ui.onEdt(() -> Ui.frame.setTitle(Ui.title()));
                    Ui.pushState();
                    return null;
                })
                .on("filename", a -> jarPath)
                .on("isBapp", a -> jarPath.replace('\\', '/').contains("/.BurpSuite/bapps/"))
                .on("unload", a -> {
                    unloadHandlers();
                    Ui.dispose();
                    Wire.event("info", "extension unloaded itself");
                    Wire.out.flush();
                    System.exit(0);
                    return null;
                })
                .on("registerUnloadingHandler", a -> register(UNLOADING, (ExtensionUnloadingHandler) a[0]))
                .as(Extension.class);
    }

    static BurpSuite burpSuite() {
        Version version = Api.obj()
                .on("name", a -> "WebProbe")
                .on("major", a -> "1")
                .on("minor", a -> "0")
                .on("build", a -> "0")
                .on("buildNumber", a -> 0L)
                .on("edition", a -> BurpSuiteEdition.COMMUNITY_EDITION)
                .text("WebProbe 1.0 (Montoya bridge)")
                .as(Version.class);
        TaskExecutionEngine engine = Api.obj()
                .on("getState", a -> taskState)
                .on("setState", a -> {
                    taskState = (TaskExecutionEngine.TaskExecutionEngineState) a[0];
                    Wire.event("info", "task execution engine set to " + taskState + " (WebProbe's own tasks are not paused by extensions)");
                    return null;
                })
                .as(TaskExecutionEngine.class);
        return Api.obj()
                .on("version", a -> version)
                .on("commandLineArguments", a -> List.of())
                .on("taskExecutionEngine", a -> engine)
                .as(BurpSuite.class);
    }

    static burp.api.montoya.proxy.Proxy proxy() {
        Api.Obj o = Api.obj()
                .on("registerRequestHandler", a -> register(PROXY_REQUEST, (ProxyRequestHandler) a[0]))
                .on("registerResponseHandler", a -> register(PROXY_RESPONSE, (ProxyResponseHandler) a[0]));
        Engine.proxyApi(o);
        return o.as(burp.api.montoya.proxy.Proxy.class);
    }

    static Http http() {
        return Api.obj()
                .on("registerHttpHandler", a -> register(HTTP_HANDLERS, (HttpHandler) a[0]))
                .on("cookieJar", a -> Engine.cookieJar())
                .on("createResponseKeywordsAnalyzer", a -> keywordAnalyzer(a[0]))
                .on("createResponseVariationsAnalyzer", a -> new VariationAnalysis())
                .on("registerSessionHandlingAction", a -> Engine.reg(Engine.SESSION_ACTIONS, (burp.api.montoya.http.sessions.SessionHandlingAction) a[0]))
                .on("sendRequest", a -> send((HttpRequest) a[0]))
                .on("sendRequests", a -> {
                    List<HttpRequestResponse> out = new ArrayList<>();
                    for (Object r : Messages.many(new Object[] { a[0] })) out.add(send((HttpRequest) r));
                    return out;
                })
                .as(Http.class);
    }

    @SuppressWarnings("unchecked")
    private static Object keywordAnalyzer(Object keywords) {
        return new KeywordAnalysis((List<String>) keywords);
    }

    /** Http.sendRequest: through WebProbe's own sender (upstream proxy,
     *  session rules and cookie jar as for any WebProbe tool). A failed send
     *  gives a request/response with no response, as in Burp. */
    static HttpRequestResponse send(HttpRequest req) {
        burp.api.montoya.http.HttpService svc = req.httpService();
        String[] err = { null };
        byte[] resp = Wire.sendRequest(req.toByteArray().getBytes(), svc.host(), svc.port(), svc.secure(), err);
        if (resp == null) Logs.error("sendRequest to " + svc + " failed: " + err[0]);
        HttpResponse response = resp == null ? null : (HttpResponse) Messages.response(resp, null, HttpResponse.class);
        return Messages.requestResponse(req, response, Messages.annotations("", HighlightColor.NONE));
    }
}
