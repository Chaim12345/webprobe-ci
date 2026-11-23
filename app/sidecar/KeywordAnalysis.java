// Case-insensitive keyword counts over the complete HTTP response, matching
// real Burp 2026.11.2 (docs/parity/2026-11-22-real-burp): `token` and `TOKEN`
// vary together, and an empty keyword is accepted. Each analyzer retains only
// one count per keyword and the variant set, never the responses. Counts use
// non-overlapping matches. Case folding is locale-independent (Locale.ROOT);
// Unicode case behavior beyond ASCII was not measured against Burp.
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.responses.analysis.ResponseKeywordsAnalyzer;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;

final class KeywordAnalysis implements ResponseKeywordsAnalyzer {
    /** One keyword: the configured spelling, its folded match form, its count. */
    private static final class Entry {
        final String keyword;
        final String folded;
        int count;

        Entry(String keyword) {
            this.keyword = keyword;
            this.folded = keyword.toLowerCase(Locale.ROOT);
        }
    }

    private final List<Entry> entries = new ArrayList<>();
    private final Set<String> variants = new LinkedHashSet<>();
    private boolean initialized;

    KeywordAnalysis(List<String> keywords) {
        for (String keyword : List.copyOf(keywords)) {
            boolean seen = false;
            for (Entry e : entries) seen |= e.keyword.equals(keyword);
            if (!seen) entries.add(new Entry(keyword));
        }
    }

    @Override
    public synchronized Set<String> variantKeywords() {
        return Set.copyOf(variants);
    }

    @Override
    public synchronized Set<String> invariantKeywords() {
        if (!initialized) return Set.of();
        Set<String> result = new LinkedHashSet<>();
        for (Entry e : entries) result.add(e.keyword);
        result.removeAll(variants);
        return Set.copyOf(result);
    }

    @Override
    public synchronized void updateWith(HttpResponse response) {
        String raw = Objects.requireNonNull(response, "response").toString();
        String folded = raw.toLowerCase(Locale.ROOT);
        for (Entry e : entries) {
            if (variants.contains(e.keyword)) continue;
            int count = count(folded, e.folded);
            if (!initialized) e.count = count;
            else if (count != e.count) variants.add(e.keyword);
        }
        initialized = true;
    }

    /** Non-overlapping occurrences of a folded keyword in the folded response.
     *  An empty keyword sits between (and around) characters, length + 1. */
    private static int count(String foldedText, String foldedKeyword) {
        if (foldedKeyword.isEmpty()) return foldedText.length() + 1;
        int count = 0;
        for (int start = 0, match; (match = foldedText.indexOf(foldedKeyword, start)) >= 0; start = match + foldedKeyword.length()) count++;
        return count;
    }
}
