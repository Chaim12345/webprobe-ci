// R-20: exercise response variation analysis through the public Montoya API.
// The factory used to throw UnsupportedOperationException; real Burp
// 2026.11.2 returns an analyzer (docs/parity/2026-11-22-real-burp). This is a
// purpose-built test extension, not evidence of unmodified BApp parity.
import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.responses.analysis.AttributeType;
import java.util.EnumSet;

public class VariationAnalysisExtension implements BurpExtension {
    private static void check(boolean ok, String message) {
        if (!ok) throw new AssertionError(message);
    }

    private static final String PAGE_A =
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nSet-Cookie: sid=1\r\n\r\n"
            + "<html><head><title>Home</title></head><body><h1>Hi</h1>"
            + "<a href=\"/x\">go</a><div id=\"main\" class=\"wrap wide\">text one</div></body></html>";
    private static final String PAGE_B =
            "HTTP/1.1 404 OK\r\nContent-Type: text/html\r\nSet-Cookie: sid=1\r\n\r\n"
            + "<html><head><title>Gone</title></head><body><h1>Hi</h1>"
            + "<a href=\"/x\">go</a><div id=\"main\" class=\"wrap wide\">text two</div></body></html>";

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("Variation analysis regression");
        var analyzer = api.http().createResponseVariationsAnalyzer();
        check(analyzer.variantAttributes().isEmpty(), "no variants before any response");
        check(analyzer.invariantAttributes().isEmpty(), "no invariants before any response");
        analyzer.updateWith(HttpResponse.httpResponse(PAGE_A));
        check(analyzer.variantAttributes().isEmpty(), "first response only seeds");
        check(analyzer.invariantAttributes().equals(EnumSet.allOf(AttributeType.class)), "first response seeds every attribute");
        var seeded = analyzer.invariantAttributes();
        analyzer.updateWith(HttpResponse.httpResponse(PAGE_B));
        var expectedVariant = EnumSet.of(AttributeType.STATUS_CODE, AttributeType.PAGE_TITLE,
                AttributeType.BODY_CONTENT, AttributeType.LIMITED_BODY_CONTENT,
                AttributeType.INITIAL_CONTENT, AttributeType.VISIBLE_TEXT);
        check(analyzer.variantAttributes().equals(expectedVariant), "status, title and body-derived attributes vary: " + analyzer.variantAttributes());
        check(analyzer.invariantAttributes().contains(AttributeType.COOKIE_NAMES), "cookie names stay invariant");
        check(analyzer.invariantAttributes().contains(AttributeType.CONTENT_LENGTH), "equal-length bodies keep content length invariant");
        check(analyzer.invariantAttributes().contains(AttributeType.TAG_NAMES), "tag names stay invariant");
        check(analyzer.invariantAttributes().contains(AttributeType.DIV_IDS), "div ids stay invariant");
        analyzer.updateWith(HttpResponse.httpResponse(PAGE_A));
        check(analyzer.variantAttributes().equals(expectedVariant), "variants persist after returning to baseline");
        check(seeded.size() == AttributeType.values().length, "returned sets are snapshots");
        var independent = api.http().createResponseVariationsAnalyzer();
        independent.updateWith(HttpResponse.httpResponse(PAGE_B));
        check(independent.variantAttributes().isEmpty(), "analyzers have independent state");
        try {
            seeded.clear();
            throw new AssertionError("returned sets must not be mutable");
        } catch (UnsupportedOperationException expected) { }
        try {
            analyzer.updateWith(null);
            throw new AssertionError("null responses must be rejected");
        } catch (NullPointerException expected) { }
        // Large attacker-controlled unquoted attributes cannot exhaust the regex stack.
        var large = api.http().createResponseVariationsAnalyzer();
        String largeResponse = "HTTP/1.1 200 OK\r\n\r\n<div data-x=" + "a".repeat(100000) + ">hello</div>";
        large.updateWith(HttpResponse.httpResponse(largeResponse));
        large.updateWith(HttpResponse.httpResponse(largeResponse));
        check(large.variantAttributes().isEmpty(), "large attributes are stable and stack-safe");
        for (String fragment : new String[] { "<!--", "<a '", "<script>" }) {
            String hostile = fragment.repeat((1024 * 1024 / fragment.length()) + 1);
            var bounded = api.http().createResponseVariationsAnalyzer();
            long started = System.nanoTime();
            bounded.updateWith(HttpResponse.httpResponse("HTTP/1.1 200 OK\r\n\r\n" + hostile));
            check(System.nanoTime() - started < java.util.concurrent.TimeUnit.SECONDS.toNanos(5),
                    "hostile one-MiB body must finish within five seconds");
        }
        var capped = api.http().createResponseVariationsAnalyzer();
        String prefix = "x".repeat(1024 * 1024);
        capped.updateWith(HttpResponse.httpResponse("HTTP/1.1 200 OK\r\n\r\n" + prefix + "one"));
        capped.updateWith(HttpResponse.httpResponse("HTTP/1.1 200 OK\r\n\r\n" + prefix + "two"));
        check(capped.variantAttributes().isEmpty(), "content beyond the body cap is not analyzed");
        capped.updateWith(HttpResponse.httpResponse("HTTP/1.1 200 OK\r\n\r\n" + prefix + "longer"));
        check(capped.variantAttributes().equals(java.util.Set.of(AttributeType.CONTENT_LENGTH)),
                "content length remains the full body byte length after truncation");
        api.logging().logToOutput("variation analysis regression passed");
    }
}
