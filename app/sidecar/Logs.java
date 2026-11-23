// Logs.java: MontoyaApi.logging(). Output and error go to the bridge's
// stderr, which WebProbe shows in the extension's output / error pane
// ("[out]" / "[error]" lines); raise*Event goes to WebProbe's event log.

import burp.api.montoya.logging.Logging;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;

final class Logs {
    private Logs() {}

    static synchronized void output(String s) {
        for (String line : String.valueOf(s).split("\n", -1)) System.err.println("[out] " + line);
    }

    static synchronized void error(String s) {
        for (String line : String.valueOf(s).split("\n", -1)) System.err.println("[error] " + line);
    }

    static String trace(Throwable t) {
        StringWriter w = new StringWriter();
        t.printStackTrace(new PrintWriter(w));
        return w.toString().stripTrailing();
    }

    /** A PrintStream that hands each completed line to `sink`. */
    static PrintStream lines(java.util.function.Consumer<String> sink) {
        OutputStream os = new OutputStream() {
            final ByteArrayOutputStream buf = new ByteArrayOutputStream();
            @Override public synchronized void write(int b) {
                if (b == '\n') flushLine(); else buf.write(b);
            }
            @Override public synchronized void flush() { if (buf.size() > 0) flushLine(); }
            private void flushLine() {
                sink.accept(buf.toString(StandardCharsets.UTF_8));
                buf.reset();
            }
        };
        return new PrintStream(os, true, StandardCharsets.UTF_8);
    }

    static final PrintStream OUT = lines(Logs::output);
    static final PrintStream ERR = lines(Logs::error);

    static Logging logging() {
        return Api.obj()
                .on("output", a -> OUT)
                .on("error", a -> ERR)
                .on("logToOutput", a -> { output(String.valueOf(a[0])); return null; })
                .on("logToError", 1, a -> {
                    if (a[0] instanceof Throwable t) error(trace(t)); else error(String.valueOf(a[0]));
                    return null;
                })
                .on("logToError", 2, a -> {
                    error(String.valueOf(a[0]));
                    if (a[1] instanceof Throwable t) error(trace(t));
                    return null;
                })
                .on("raiseDebugEvent", a -> { Wire.event("debug", String.valueOf(a[0])); return null; })
                .on("raiseInfoEvent", a -> { Wire.event("info", String.valueOf(a[0])); return null; })
                .on("raiseErrorEvent", a -> { Wire.event("error", String.valueOf(a[0])); return null; })
                .on("raiseCriticalEvent", a -> { Wire.event("critical", String.valueOf(a[0])); return null; })
                .text("Logging")
                .as(Logging.class);
    }
}
