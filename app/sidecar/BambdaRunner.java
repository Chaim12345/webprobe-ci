// Runs one already-compiled Bambda against a snapshot of recorded exchanges.
// This is a process isolation/timeout boundary, NOT a Java security sandbox.
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.internal.ObjectFactoryLocator;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.utilities.Utilities;
import java.io.PrintStream;
import java.lang.reflect.InvocationTargetException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

public final class BambdaRunner {
    private BambdaRunner() {}
    static byte[] bytes(Object value) {
        List<?> values = (List<?>) value;
        byte[] out = new byte[values.size()];
        for (int i = 0; i < out.length; i++) out[i] = ((Number) values.get(i)).byteValue();
        return out;
    }
    static ProxyHttpRequestResponse exchange(Map<String,Object> row) {
        Messages.Svc svc = new Messages.Svc(Wire.str(row, "host", ""), (int) Wire.num(row.get("port")), Boolean.TRUE.equals(row.get("secure")));
        HttpRequest req = (HttpRequest) Messages.request(bytes(row.get("request")), svc, null, HttpRequest.class);
        HttpResponse resp = row.get("response") == null ? null : (HttpResponse) Messages.response(bytes(row.get("response")), null, HttpResponse.class);
        return Api.obj()
            .on("request", a -> req)
            .on("response", a -> resp)
            .on("hasResponse", a -> resp != null)
            .on("httpService", a -> req.httpService())
            .on("url", a -> req.url()).on("method", a -> req.method()).on("path", a -> req.path())
            .on("host", a -> svc.host()).on("port", a -> svc.port()).on("secure", a -> svc.secure())
            .on("httpServiceString", a -> svc.origin()).on("requestHttpVersion", a -> req.httpVersion())
            .on("requestBody", a -> req.bodyToString())
            .on("id", a -> Integer.parseInt(Wire.str(row, "id", "0")))
            .on("contains", 1, a -> ((Pattern) a[0]).matcher(req.toString() + (resp == null ? "" : resp.toString())).find())
            .on("contains", 2, a -> {
                String text = req.toString() + (resp == null ? "" : resp.toString());
                String needle = (String) a[0];
                return (Boolean) a[1] ? text.contains(needle) : text.toLowerCase(java.util.Locale.ROOT).contains(needle.toLowerCase(java.util.Locale.ROOT));
            })
            .as(ProxyHttpRequestResponse.class);
    }
    private static void watchParent(long expectedPid) {
        ProcessHandle parent = ProcessHandle.current().parent().orElse(null);
        if (parent == null || parent.pid() != expectedPid || !parent.isAlive())
            Runtime.getRuntime().halt(72);
        Thread guard = new Thread(() -> {
            try { parent.onExit().join(); }
            finally { Runtime.getRuntime().halt(72); }
        }, "bambda-parent-watchdog");
        guard.setDaemon(true);
        guard.start();
    }
    public static void main(String[] args) throws Exception {
        watchParent(Long.parseLong(args[1]));
        PrintStream protocol = System.out;
        // A user println must not corrupt the row-result protocol or fill a pipe.
        System.setOut(new PrintStream(java.io.OutputStream.nullOutputStream()));
        System.setErr(new PrintStream(java.io.OutputStream.nullOutputStream()));
        ObjectFactoryLocator.FACTORY = Factory.create();
        var method = Class.forName("WebProbeUserBambda").getMethod("evaluate", ProxyHttpRequestResponse.class, Utilities.class);
        Object parsed = Wire.Json.parse(Files.readString(Path.of(args[0]), StandardCharsets.UTF_8));
        for (Object item : (List<?>) parsed) {
            @SuppressWarnings("unchecked") Map<String,Object> row = (Map<String,Object>) item;
            String prefix = "{\"id\":" + Wire.str(row, "id", "0");
            try {
                Object value = method.invoke(null, exchange(row), Utils.utilities());
                String json;
                if (value == null) json = "null";
                else if (value instanceof Boolean || value instanceof Byte || value instanceof Short || value instanceof Integer || value instanceof Long) json = value.toString();
                else if (value instanceof Double d && Double.isFinite(d) || value instanceof Float f && Float.isFinite(f)) json = value.toString();
                else {
                    String text = value.toString();
                    if (text.length() > 65536) throw new IllegalArgumentException("column value exceeds 65536 characters");
                    json = Wire.Json.esc(text);
                }
                protocol.println(prefix + ",\"value\":" + json + "}");
            } catch (Throwable failure) {
                Throwable cause = failure instanceof InvocationTargetException ? failure.getCause() : failure;
                String text = cause.getClass().getSimpleName() + ": " + cause.getMessage();
                if (text.length() > 4096) text = text.substring(0, 4096);
                protocol.println(prefix + ",\"error\":" + Wire.Json.esc(text) + "}");
            }
        }
    }
}
