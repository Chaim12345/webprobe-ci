// R-20: exercise response keyword analysis through the public Montoya API.
// Case-insensitive counting and empty keywords match real Burp 2026.11.2
// (docs/parity/2026-11-22-real-burp). This is a purpose-built test extension,
// not evidence of unmodified BApp parity.
import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.responses.HttpResponse;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

public class KeywordAnalysisExtension implements BurpExtension {
    private static void check(boolean ok, String message) {
        if (!ok) throw new AssertionError(message);
    }

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("Keyword analysis regression");
        var keywords = new ArrayList<>(List.of("token", "absent", "TOKEN", "X-Flag", "token"));
        var analyzer = api.http().createResponseKeywordsAnalyzer(keywords);
        keywords.clear(); // The analyzer owns a snapshot, not the caller's mutable list.
        check(analyzer.variantKeywords().isEmpty(), "no variants before any response");
        check(analyzer.invariantKeywords().isEmpty(), "no invariants before any response");
        analyzer.updateWith(HttpResponse.httpResponse("HTTP/1.1 200 OK\r\nX-Flag: yes\r\n\r\ntoken token TOKEN"));
        check(analyzer.invariantKeywords().equals(Set.of("token", "absent", "TOKEN", "X-Flag")), "first response seeds all keywords");
        var firstSnapshot = analyzer.invariantKeywords();
        analyzer.updateWith(HttpResponse.httpResponse("HTTP/1.1 200 OK\r\nX-Flag: yes\r\n\r\ntoken TOKEN"));
        check(analyzer.variantKeywords().equals(Set.of("token", "TOKEN")), "counting is case-insensitive: token and TOKEN vary together");
        check(analyzer.invariantKeywords().equals(Set.of("absent", "X-Flag")), "absent keywords have stable zero count");
        check(firstSnapshot.size() == 4, "returned sets are snapshots");
        analyzer.updateWith(HttpResponse.httpResponse("HTTP/1.1 200 OK\r\n\r\ntoken token TOKEN"));
        check(analyzer.variantKeywords().equals(Set.of("token", "TOKEN", "X-Flag")), "variants persist and include response headers");
        check(analyzer.invariantKeywords().equals(Set.of("absent")), "only the absent keyword stays invariant");
        var independent = api.http().createResponseKeywordsAnalyzer(List.of("token"));
        independent.updateWith(HttpResponse.httpResponse("HTTP/1.1 200 OK\r\n\r\ntoken"));
        check(independent.invariantKeywords().equals(Set.of("token")), "analyzers have independent state");
        var repeated = api.http().createResponseKeywordsAnalyzer(List.of("aa"));
        repeated.updateWith(HttpResponse.httpResponse("HTTP/1.1 200 OK\r\n\r\naaaa"));
        repeated.updateWith(HttpResponse.httpResponse("HTTP/1.1 200 OK\r\n\r\naaaaa"));
        check(repeated.invariantKeywords().equals(Set.of("aa")), "matches are non-overlapping");
        var empty = api.http().createResponseKeywordsAnalyzer(List.of(""));
        empty.updateWith(HttpResponse.httpResponse("HTTP/1.1 200 OK\r\n\r\nab"));
        check(empty.invariantKeywords().equals(Set.of("")), "empty keywords are accepted, as in Burp");
        empty.updateWith(HttpResponse.httpResponse("HTTP/1.1 200 OK\r\n\r\nabc"));
        check(empty.variantKeywords().equals(Set.of("")), "an empty keyword still tracks response length");
        try {
            firstSnapshot.clear();
            throw new AssertionError("returned sets must not be mutable");
        } catch (UnsupportedOperationException expected) { }
        try {
            analyzer.updateWith(null);
            throw new AssertionError("null responses must be rejected");
        } catch (NullPointerException expected) { }
        api.logging().logToOutput("keyword analysis regression passed");
    }
}
