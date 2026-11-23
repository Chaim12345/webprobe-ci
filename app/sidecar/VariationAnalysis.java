// Attribute-based response variation analysis, the object behind
// http().createResponseVariationsAnalyzer (previously UnsupportedOperation-
// Exception; real Burp 2026.11.2 returns an analyzer, see
// docs/parity/2026-11-22-real-burp). The first response seeds every
// AttributeType's extracted value; an attribute whose value later differs
// stays variant. The analyzer retains the first extracted attribute values,
// including body content, but not HttpResponse objects. HTML-derived attributes
// come from one small tag scan of the
// body; header and body extraction are deterministic, not a byte-for-byte
// copy of Burp's internal metrics (INITIAL_CONTENT and LIMITED_BODY_CONTENT
// prefixes are WebProbe's documented choices).
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.responses.analysis.AttributeType;
import burp.api.montoya.http.message.responses.analysis.ResponseVariationsAnalyzer;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;

final class VariationAnalysis implements ResponseVariationsAnalyzer {
    /** Length of the INITIAL_CONTENT body prefix. */
    private static final int INITIAL_LEN = 256;
    /** Length cap of the LIMITED_BODY_CONTENT value. */
    private static final int LIMITED_LEN = 4096;

    /** Parse at most the first MiB of body bytes; length remains the full byte length. */
    private static final int MAX_BODY_BYTES = 1024 * 1024;

    /** One parsed start tag and its end offset in the bounded body. */
    private record Tag(String name, Map<String, String> attrs, int end) {}

    private final Map<AttributeType, Object> first = new EnumMap<>(AttributeType.class);
    private final Set<AttributeType> variants = EnumSet.noneOf(AttributeType.class);
    private boolean initialized;

    @Override
    public synchronized Set<AttributeType> variantAttributes() {
        return Set.copyOf(variants);
    }

    @Override
    public synchronized Set<AttributeType> invariantAttributes() {
        if (!initialized) return Set.of();
        EnumSet<AttributeType> all = EnumSet.allOf(AttributeType.class);
        all.removeAll(variants);
        return Set.copyOf(all);
    }

    @Override
    public synchronized void updateWith(HttpResponse response) {
        Objects.requireNonNull(response, "response");
        Map<String, List<String>> headers = new java.util.LinkedHashMap<>();
        for (HttpHeader h : response.headers())
            headers.computeIfAbsent(h.name().toLowerCase(Locale.ROOT), k -> new ArrayList<>()).add(h.value());
        byte[] bodyBytes = response.body().getBytes();
        String body = new String(bodyBytes, 0, Math.min(bodyBytes.length, MAX_BODY_BYTES), java.nio.charset.StandardCharsets.ISO_8859_1);
        List<Tag> tags = tags(body);
        for (AttributeType type : AttributeType.values()) {
            if (variants.contains(type)) continue;
            Object value = extract(type, response.statusCode(), bodyBytes.length, headers, body, tags);
            if (!initialized) first.put(type, value);
            else if (!Objects.equals(first.get(type), value)) variants.add(type);
        }
        initialized = true;
    }

    private static Object extract(AttributeType type, int status, int bodyLength, Map<String, List<String>> headers, String body, List<Tag> tags) {
        switch (type) {
            case STATUS_CODE: return status;
            case ETAG_HEADER: return header(headers, "etag");
            case LAST_MODIFIED_HEADER: return header(headers, "last-modified");
            case CONTENT_TYPE: {
                String v = header(headers, "content-type");
                int semi = v.indexOf(';');
                return (semi < 0 ? v : v.substring(0, semi)).trim().toLowerCase(Locale.ROOT);
            }
            case CONTENT_LENGTH: return bodyLength;
            case CONTENT_LOCATION: return header(headers, "content-location");
            case LOCATION: return header(headers, "location");
            case COOKIE_NAMES: {
                Set<String> names = new TreeSet<>();
                for (String v : headers.getOrDefault("set-cookie", List.of())) {
                    int eq = v.indexOf('=');
                    names.add((eq < 0 ? v : v.substring(0, eq)).trim());
                }
                return names;
            }
            case HEADER_NAMES: return new TreeSet<>(headers.keySet());
            case TAG_NAMES: {
                Set<String> names = new TreeSet<>();
                for (Tag t : tags) names.add(t.name());
                return names;
            }
            case TAG_IDS: {
                Set<String> ids = new TreeSet<>();
                for (Tag t : tags) if (t.attrs().containsKey("id")) ids.add(t.attrs().get("id"));
                return ids;
            }
            case DIV_IDS: {
                Set<String> ids = new TreeSet<>();
                for (Tag t : tags) if (t.name().equals("div") && t.attrs().containsKey("id")) ids.add(t.attrs().get("id"));
                return ids;
            }
            case BODY_CONTENT: return body;
            case LIMITED_BODY_CONTENT: return body.substring(0, Math.min(LIMITED_LEN, body.length()));
            case INITIAL_CONTENT: return body.substring(0, Math.min(INITIAL_LEN, body.length()));
            case VISIBLE_TEXT: return visibleText(body);
            case WORD_COUNT: return wordCount(body);
            case VISIBLE_WORD_COUNT: return wordCount(visibleText(body));
            case COMMENTS: return comments(body);
            case PAGE_TITLE: return firstGroup("title", body, tags);
            case FIRST_HEADER_TAG: return firstGroup("heading", body, tags);
            case HEADER_TAGS: return allGroups("heading", body, tags);
            case ANCHOR_LABELS: return allGroups("a", body, tags);
            case BUTTON_SUBMIT_LABELS: return allGroups("button", body, tags);
            case INPUT_SUBMIT_LABELS: return inputLabels(tags, "submit");
            case INPUT_IMAGE_LABELS: return inputLabels(tags, "image");
            case NON_HIDDEN_FORM_INPUT_TYPES: {
                List<String> out = new ArrayList<>();
                for (Tag t : tags) {
                    if (!t.name().equals("input")) continue;
                    String kind = t.attrs().getOrDefault("type", "text").toLowerCase(Locale.ROOT);
                    if (!kind.equals("hidden")) out.add(kind);
                }
                return out;
            }
            case CSS_CLASSES: {
                Set<String> classes = new TreeSet<>();
                for (Tag t : tags)
                    for (String c : t.attrs().getOrDefault("class", "").split("\\s+"))
                        if (!c.isEmpty()) classes.add(c);
                return classes;
            }
            case LINE_COUNT: {
                if (body.isEmpty()) return 0;
                int lines = 1;
                for (int i = 0; i < body.length(); i++) if (body.charAt(i) == '\n') lines++;
                return lines;
            }
            case COLON_COUNT: {
                int n = 0;
                for (int i = 0; i < body.length(); i++) if (body.charAt(i) == ':') n++;
                return n;
            }
            case OUTBOUND_EDGE_COUNT: return edgeTags(tags).size();
            case OUTBOUND_EDGE_TAG_NAMES: {
                Set<String> names = new TreeSet<>();
                for (Tag t : edgeTags(tags)) names.add(t.name());
                return names;
            }
            case CANONICAL_LINK: {
                for (Tag t : tags)
                    if (t.name().equals("link") && t.attrs().getOrDefault("rel", "").equalsIgnoreCase("canonical"))
                        return t.attrs().getOrDefault("href", "");
                return "";
            }
            default: return "";
        }
    }

    private static String header(Map<String, List<String>> headers, String name) {
        List<String> v = headers.get(name);
        return v == null || v.isEmpty() ? "" : v.get(0);
    }

    /** Tags carrying an outbound edge: a[href], img/script/iframe[src],
     *  link[href], form[action]. */
    private static List<Tag> edgeTags(List<Tag> tags) {
        List<Tag> out = new ArrayList<>();
        for (Tag t : tags) {
            boolean edge = switch (t.name()) {
                case "a", "link" -> t.attrs().containsKey("href");
                case "img", "script", "iframe" -> t.attrs().containsKey("src");
                case "form" -> t.attrs().containsKey("action");
                default -> false;
            };
            if (edge) out.add(t);
        }
        return out;
    }

    private static List<String> inputLabels(List<Tag> tags, String type) {
        List<String> out = new ArrayList<>();
        for (Tag t : tags) {
            if (!t.name().equals("input")) continue;
            if (!t.attrs().getOrDefault("type", "text").equalsIgnoreCase(type)) continue;
            String label = t.attrs().getOrDefault("value", t.attrs().getOrDefault("alt", ""));
            out.add(label);
        }
        return out;
    }

    private static List<String> comments(String body) {
        List<String> out = new ArrayList<>();
        int cursor = 0;
        while (cursor < body.length()) {
            int start = body.indexOf("<!--", cursor);
            if (start < 0) break;
            int end = body.indexOf("-->", start + 4);
            if (end < 0) break;
            out.add(body.substring(start + 4, end).trim());
            cursor = end + 3;
        }
        return out;
    }

    private static String visibleText(String body) {
        String lower = body.toLowerCase(Locale.ROOT);
        StringBuilder out = new StringBuilder();
        int cursor = 0;
        while (cursor < body.length()) {
            if (body.startsWith("<!--", cursor)) {
                int end = body.indexOf("-->", cursor + 4);
                cursor = end < 0 ? body.length() : end + 3;
                out.append(' ');
            } else if (body.charAt(cursor) == '<') {
                int end = body.indexOf('>', cursor + 1);
                if (end < 0) break;
                String name = lower.substring(cursor + 1, end).trim();
                int boundary = 0;
                while (boundary < name.length() && Character.isLetter(name.charAt(boundary))) boundary++;
                name = name.substring(0, boundary);
                if (name.equals("script") || name.equals("style")) {
                    int close = lower.indexOf("</" + name, end + 1);
                    if (close < 0) break;
                    int closeEnd = body.indexOf('>', close);
                    cursor = closeEnd < 0 ? body.length() : closeEnd + 1;
                } else cursor = end + 1;
                out.append(' ');
            } else {
                char c = body.charAt(cursor++);
                if (Character.isWhitespace(c)) {
                    if (out.length() > 0 && out.charAt(out.length() - 1) != ' ') out.append(' ');
                } else out.append(c);
            }
        }
        return out.toString().trim();
    }

    private static int wordCount(String text) {
        int count = 0;
        boolean inWord = false;
        for (int i = 0; i < text.length(); i++) {
            if (Character.isWhitespace(text.charAt(i))) inWord = false;
            else if (!inWord) { count++; inWord = true; }
        }
        return count;
    }

    private static String firstGroup(String kind, String body, List<Tag> tags) {
        List<String> groups = allGroups(kind, body, tags);
        return groups.isEmpty() ? "" : groups.get(0);
    }

    // Searches advance past every consumed element. A missing closer stops
    // the scan instead of retrying every remaining opening tag.
    private static List<String> allGroups(String kind, String body, List<Tag> tags) {
        List<String> out = new ArrayList<>();
        String lower = body.toLowerCase(Locale.ROOT);
        int cursor = 0;
        for (Tag t : tags) {
            if (t.end() < cursor) continue;
            boolean heading = t.name().length() == 2 && t.name().charAt(0) == 'h'
                    && t.name().charAt(1) >= '1' && t.name().charAt(1) <= '6';
            if (!(kind.equals("heading") ? heading : t.name().equals(kind))) continue;
            int close = lower.indexOf("</" + t.name(), t.end());
            if (close < 0) break;
            out.add(body.substring(t.end(), close).trim());
            cursor = close + t.name().length() + 2;
        }
        return out;
    }

    private static Map<String, String> attributes(String body, int cursor, int end) {
        Map<String, String> out = new java.util.LinkedHashMap<>();
        while (cursor < end) {
            while (cursor < end && (Character.isWhitespace(body.charAt(cursor)) || body.charAt(cursor) == '/')) cursor++;
            int start = cursor;
            while (cursor < end && !Character.isWhitespace(body.charAt(cursor)) && body.charAt(cursor) != '=') cursor++;
            if (cursor == start) { cursor++; continue; }
            String name = body.substring(start, cursor).toLowerCase(Locale.ROOT);
            while (cursor < end && Character.isWhitespace(body.charAt(cursor))) cursor++;
            if (cursor >= end || body.charAt(cursor) != '=') continue;
            cursor++;
            while (cursor < end && Character.isWhitespace(body.charAt(cursor))) cursor++;
            char quote = cursor < end ? body.charAt(cursor) : 0;
            boolean quoted = quote == '\'' || quote == '"';
            if (quoted) cursor++;
            start = cursor;
            while (cursor < end && (quoted ? body.charAt(cursor) != quote : !Character.isWhitespace(body.charAt(cursor)))) cursor++;
            out.put(name, body.substring(start, cursor));
            if (quoted && cursor < end) cursor++;
        }
        return out;
    }

    private static List<Tag> tags(String body) {
        List<Tag> out = new ArrayList<>();
        // Scan start tags without recursive regular-expression repetition:
        // long unquoted attribute values must not overflow the JVM stack.
        int cursor = 0;
        while (cursor < body.length()) {
            int open = body.indexOf('<', cursor);
            if (open < 0) break;
            int start = open + 1;
            while (start < body.length() && Character.isWhitespace(body.charAt(start))) start++;
            int nameEnd = start;
            while (nameEnd < body.length()) {
                char c = body.charAt(nameEnd);
                if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
                        || (nameEnd > start && c >= '0' && c <= '9'))) break;
                nameEnd++;
            }
            if (nameEnd == start) { cursor = start + 1; continue; }
            int end = nameEnd;
            char quote = 0;
            for (; end < body.length(); end++) {
                char c = body.charAt(end);
                if (quote != 0) { if (c == quote) quote = 0; }
                else if (c == '\'' || c == '"') quote = c;
                else if (c == '>') break;
            }
            if (end == body.length()) break;
            Map<String, String> attrs = attributes(body, nameEnd, end);
            out.add(new Tag(body.substring(start, nameEnd).toLowerCase(Locale.ROOT), attrs, end + 1));
            cursor = end + 1;
        }
        return out;
    }
}
