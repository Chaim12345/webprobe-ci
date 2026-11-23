// Utils.java: MontoyaApi.utilities() in plain Java: Base64, URL, HTML,
// byte, number, random, compression (gzip, deflate), crypto (the digests
// the JDK has), string and JSON (dotted / indexed paths). Brotli,
// digests the JDK lacks, shellUtils and rankingUtils are not supported.

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.utilities.Base64DecodingOptions;
import burp.api.montoya.utilities.Base64EncodingOptions;
import burp.api.montoya.utilities.CompressionType;
import burp.api.montoya.utilities.DigestAlgorithm;
import burp.api.montoya.utilities.HtmlEncoding;
import burp.api.montoya.utilities.Utilities;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;
import java.util.zip.InflaterInputStream;

final class Utils {
    private Utils() {}

    static final java.nio.charset.Charset L1 = StandardCharsets.ISO_8859_1;

    private static byte[] bytes(Object o) {
        return o instanceof ByteArray b ? b.getBytes() : o instanceof byte[] b ? b : String.valueOf(o).getBytes(L1);
    }

    private static boolean has(Object[] a, Object option) {
        for (Object o : Messages.many(new Object[] { a.length > 1 ? a[1] : new Object[0] })) if (o == option) return true;
        return false;
    }

    static Utilities utilities() {
        return Api.obj()
                .on("base64Utils", a -> base64())
                .on("urlUtils", a -> url())
                .on("htmlUtils", a -> html())
                .on("byteUtils", a -> byteUtils())
                .on("numberUtils", a -> numbers())
                .on("randomUtils", a -> random())
                .on("compressionUtils", a -> compression())
                .on("cryptoUtils", a -> crypto())
                .on("stringUtils", a -> strings())
                .on("jsonUtils", a -> Json.utils())
                .as(Utilities.class);
    }

    static burp.api.montoya.utilities.Base64Utils base64() {
        Api.Impl enc = a -> {
            Base64.Encoder e = has(a, Base64EncodingOptions.URL) ? Base64.getUrlEncoder() : Base64.getEncoder();
            if (has(a, Base64EncodingOptions.NO_PADDING)) e = e.withoutPadding();
            return e.encodeToString(bytes(a[0]));
        };
        return Api.obj()
                .on("encode", a -> Messages.bytes(((String) enc.call(a)).getBytes(L1)))
                .on("encodeToString", enc)
                .on("decode", a -> {
                    String in = new String(bytes(a[0]), L1).trim();
                    Base64.Decoder d = has(a, Base64DecodingOptions.URL) || in.contains("-") || in.contains("_") ? Base64.getUrlDecoder() : Base64.getDecoder();
                    return Messages.bytes(d.decode(in));
                })
                .as(burp.api.montoya.utilities.Base64Utils.class);
    }

    static burp.api.montoya.utilities.URLUtils url() {
        return Api.obj()
                .on("encode", a -> a[0] instanceof ByteArray b ? Messages.bytes(URLEncoder.encode(new String(b.getBytes(), L1), L1).getBytes(L1))
                        : URLEncoder.encode((String) a[0], StandardCharsets.UTF_8))
                .on("decode", a -> a[0] instanceof ByteArray b ? Messages.bytes(URLDecoder.decode(new String(b.getBytes(), L1), L1).getBytes(L1))
                        : URLDecoder.decode((String) a[0], StandardCharsets.UTF_8))
                .as(burp.api.montoya.utilities.URLUtils.class);
    }

    static burp.api.montoya.utilities.HtmlUtils html() {
        return Api.obj()
                .on("encode", a -> {
                    HtmlEncoding mode = a.length > 1 ? (HtmlEncoding) a[1] : HtmlEncoding.STANDARD;
                    StringBuilder b = new StringBuilder();
                    for (char c : ((String) a[0]).toCharArray()) {
                        boolean special = "<>\"'&".indexOf(c) >= 0;
                        if (mode == HtmlEncoding.STANDARD && !special) b.append(c);
                        else if (mode == HtmlEncoding.ALL_CHARACTERS_HEX) b.append("&#x").append(Integer.toHexString(c)).append(';');
                        else if (mode == HtmlEncoding.STANDARD || mode == HtmlEncoding.ALL_CHARACTERS) {
                            b.append(switch (c) { case '<' -> "&lt;"; case '>' -> "&gt;"; case '"' -> "&quot;"; case '\'' -> "&#39;"; case '&' -> "&amp;"; default -> "&#" + (int) c + ";"; });
                        } else b.append("&#").append((int) c).append(';');
                    }
                    return b.toString();
                })
                .on("decode", a -> {
                    java.util.regex.Matcher m = Pattern.compile("&(#x[0-9a-fA-F]+|#[0-9]+|lt|gt|quot|apos|amp);").matcher((String) a[0]);
                    StringBuilder b = new StringBuilder();
                    while (m.find()) {
                        String e = m.group(1);
                        String r = switch (e) {
                            case "lt" -> "<"; case "gt" -> ">"; case "quot" -> "\""; case "apos" -> "'"; case "amp" -> "&";
                            default -> String.valueOf((char) (e.startsWith("#x") ? Integer.parseInt(e.substring(2), 16) : Integer.parseInt(e.substring(1))));
                        };
                        m.appendReplacement(b, java.util.regex.Matcher.quoteReplacement(r));
                    }
                    m.appendTail(b);
                    return b.toString();
                })
                .as(burp.api.montoya.utilities.HtmlUtils.class);
    }

    static burp.api.montoya.utilities.ByteUtils byteUtils() {
        return Api.obj()
                .on("indexOf", a -> {
                    ByteArray hay = Messages.bytes((byte[]) a[0]);
                    Object[] rest = java.util.Arrays.copyOfRange(a, 1, a.length);
                    if (rest[0] instanceof byte[] n) rest[0] = Messages.bytes(n);
                    return switch (rest.length) {
                        case 1 -> rest[0] instanceof Pattern p ? hay.indexOf(p) : hay.indexOf((ByteArray) rest[0]);
                        case 2 -> hay.indexOf((ByteArray) rest[0], (Boolean) rest[1]);
                        case 3 -> hay.indexOf((Pattern) rest[0], (Integer) rest[1], (Integer) rest[2]);
                        default -> hay.indexOf((ByteArray) rest[0], (Boolean) rest[1], (Integer) rest[2], (Integer) rest[3]);
                    };
                })
                .on("countMatches", a -> {
                    byte[] hay = (byte[]) a[0];
                    if (a[1] instanceof Pattern p) {
                        java.util.regex.Matcher m = p.matcher(new String(hay, L1));
                        int n = 0;
                        while (m.find()) n++;
                        return n;
                    }
                    byte[] n = (byte[]) a[1];
                    boolean cs = a.length < 3 || (Boolean) a[2];
                    int from = a.length >= 5 ? (Integer) a[3] : 0, to = a.length >= 5 ? (Integer) a[4] : hay.length;
                    int count = 0, at;
                    while (n.length > 0 && (at = Messages.find(hay, n, cs, from, to)) >= 0) { count++; from = at + n.length; }
                    return count;
                })
                .on("convertToString", a -> new String((byte[]) a[0], L1))
                .on("convertFromString", a -> ((String) a[0]).getBytes(L1))
                .as(burp.api.montoya.utilities.ByteUtils.class);
    }

    static burp.api.montoya.utilities.NumberUtils numbers() {
        Api.Obj o = Api.obj();
        String[] names = { "Binary", "Octal", "Decimal", "Hex" };
        int[] radix = { 2, 8, 10, 16 };
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                if (i == j) continue;
                int from = radix[i], to = radix[j];
                o.on("convert" + names[i] + "To" + names[j], a -> {
                    String in = a[0] instanceof ByteArray b ? new BigInteger(1, b.getBytes()).toString(from) : ((String) a[0]).trim();
                    return new BigInteger(in, from).toString(to);
                });
            }
            int from = radix[i];
            o.on("convert" + names[i], a -> new BigInteger(((String) a[0]).trim(), from).toString((Integer) a[1]));
        }
        return o.as(burp.api.montoya.utilities.NumberUtils.class);
    }

    static burp.api.montoya.utilities.RandomUtils random() {
        SecureRandom rnd = new SecureRandom();
        return Api.obj()
                .on("randomString", a -> {
                    int min = (Integer) a[0], max = a.length == 3 ? (Integer) a[1] : min;
                    Object set = a[a.length - 1];
                    StringBuilder chars = new StringBuilder();
                    if (set instanceof String s) chars.append(s);
                    else for (Object cs : Messages.many(new Object[] { set })) {
                        String n = String.valueOf(cs);
                        if (n.contains("UPPER")) chars.append("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
                        else if (n.contains("LOWER")) chars.append("abcdefghijklmnopqrstuvwxyz");
                        else if (n.contains("DIGIT")) chars.append("0123456789");
                        else chars.append("!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~");
                    }
                    if (chars.length() == 0) chars.append("abcdefghijklmnopqrstuvwxyz0123456789");
                    int len = min + (max > min ? rnd.nextInt(max - min + 1) : 0);
                    StringBuilder b = new StringBuilder();
                    for (int i = 0; i < len; i++) b.append(chars.charAt(rnd.nextInt(chars.length())));
                    return b.toString();
                })
                .as(burp.api.montoya.utilities.RandomUtils.class);
    }

    static burp.api.montoya.utilities.CompressionUtils compression() {
        return Api.obj()
                .on("compress", a -> {
                    CompressionType t = (CompressionType) a[1];
                    ByteArrayOutputStream out = new ByteArrayOutputStream();
                    java.io.OutputStream z = switch (t) {
                        case GZIP -> new GZIPOutputStream(out);
                        case DEFLATE -> new DeflaterOutputStream(out);
                        default -> throw Api.unsupported("CompressionUtils", "compress(" + t + ")");
                    };
                    z.write(bytes(a[0]));
                    z.close();
                    return Messages.bytes(out.toByteArray());
                })
                .on("decompress", a -> {
                    CompressionType t = (CompressionType) a[1];
                    ByteArrayInputStream in = new ByteArrayInputStream(bytes(a[0]));
                    java.io.InputStream z = switch (t) {
                        case GZIP -> new GZIPInputStream(in);
                        case DEFLATE -> new InflaterInputStream(in);
                        default -> throw Api.unsupported("CompressionUtils", "decompress(" + t + ")");
                    };
                    return Messages.bytes(z.readAllBytes());
                })
                .as(burp.api.montoya.utilities.CompressionUtils.class);
    }

    static burp.api.montoya.utilities.CryptoUtils crypto() {
        return Api.obj()
                .on("generateDigest", a -> {
                    DigestAlgorithm alg = (DigestAlgorithm) a[1];
                    // SHA_256 -> SHA-256, SHA3_256 -> SHA3-256, SHA_512_224 -> SHA-512/224
                    String n = alg.name();
                    String jdk = n.startsWith("SHA_512_") ? "SHA-512/" + n.substring(8) : n.replaceFirst("_", "-");
                    try {
                        return Messages.bytes(MessageDigest.getInstance(jdk).digest(bytes(a[0])));
                    } catch (java.security.NoSuchAlgorithmException e) {
                        throw Api.unsupported("CryptoUtils", "generateDigest(" + alg + ")");
                    }
                })
                .as(burp.api.montoya.utilities.CryptoUtils.class);
    }

    static burp.api.montoya.utilities.StringUtils strings() {
        return Api.obj()
                .on("convertAsciiToHexString", a -> {
                    StringBuilder b = new StringBuilder();
                    for (byte x : ((String) a[0]).getBytes(L1)) b.append(String.format("%02x", x & 0xff));
                    return b.toString();
                })
                .on("convertHexStringToAscii", a -> {
                    String h = ((String) a[0]).replaceAll("\\s", "");
                    byte[] out = new byte[h.length() / 2];
                    for (int i = 0; i < out.length; i++) out[i] = (byte) Integer.parseInt(h.substring(2 * i, 2 * i + 2), 16);
                    return new String(out, L1);
                })
                .as(burp.api.montoya.utilities.StringUtils.class);
    }

    /** JsonUtils over paths like `a.b[0].c` (a leading `$.` is allowed). */
    static final class Json {
        static burp.api.montoya.utilities.json.JsonUtils utils() {
            return Api.obj()
                    .on("isValidJson", a -> { try { parse((String) a[0]); return true; } catch (RuntimeException e) { return false; } })
                    .on("read", a -> { Object v = get(parse((String) a[0]), (String) a[1]); return v == null ? null : write(v); })
                    .on("readString", a -> { Object v = get(parse((String) a[0]), (String) a[1]); return v == null ? null : v instanceof String s ? s : write(v); })
                    .on("readBoolean", a -> (Boolean) get(parse((String) a[0]), (String) a[1]))
                    .on("readDouble", a -> { Object v = get(parse((String) a[0]), (String) a[1]); return v == null ? null : ((Number) v).doubleValue(); })
                    .on("readLong", a -> { Object v = get(parse((String) a[0]), (String) a[1]); return v == null ? null : ((Number) v).longValue(); })
                    .on("add", a -> edit((String) a[0], (String) a[1], parse((String) a[2]), true))
                    .on("update", a -> edit((String) a[0], (String) a[1], parse((String) a[2]), false))
                    .on("remove", a -> edit((String) a[0], (String) a[1], null, false))
                    .as(burp.api.montoya.utilities.json.JsonUtils.class);
        }

        static Object parse(String s) {
            Wire.Json j = new Wire.Json(s);
            j.ws();
            Object v = j.value();
            j.ws();
            if (j.i != s.length()) throw new IllegalArgumentException("trailing data in JSON");
            return v;
        }

        private static List<Object> steps(String path) {
            List<Object> out = new ArrayList<>();
            String p = path.startsWith("$") ? path.substring(1) : path;
            java.util.regex.Matcher m = Pattern.compile("\\.?([^.\\[\\]]+)|\\[(\\d+)\\]").matcher(p);
            while (m.find()) out.add(m.group(2) != null ? (Object) Integer.parseInt(m.group(2)) : m.group(1));
            return out;
        }

        @SuppressWarnings("unchecked")
        static Object get(Object root, String path) {
            Object cur = root;
            for (Object s : steps(path)) {
                if (s instanceof Integer i && cur instanceof List<?> l) cur = i < l.size() ? l.get(i) : null;
                else if (cur instanceof Map<?, ?> m) cur = ((Map<String, Object>) m).get(String.valueOf(s));
                else return null;
            }
            return cur;
        }

        @SuppressWarnings("unchecked")
        static String edit(String json, String path, Object value, boolean add) {
            Object root = ordered(parse(json));
            List<Object> st = steps(path);
            Object cur = root;
            for (int k = 0; k < st.size() - 1; k++) {
                Object s = st.get(k);
                cur = s instanceof Integer i ? ((List<Object>) cur).get(i) : ((Map<String, Object>) cur).get(String.valueOf(s));
            }
            Object last = st.get(st.size() - 1);
            if (cur instanceof List<?> l) {
                List<Object> list = (List<Object>) l;
                int i = (Integer) last;
                if (value == null) list.remove(i); else if (add) list.add(i, value); else list.set(i, value);
            } else {
                Map<String, Object> map = (Map<String, Object>) cur;
                if (value == null) map.remove(String.valueOf(last)); else map.put(String.valueOf(last), value);
            }
            return write(root);
        }

        @SuppressWarnings("unchecked")
        private static Object ordered(Object v) {
            if (v instanceof Map<?, ?> m) {
                Map<String, Object> out = new LinkedHashMap<>();
                for (Map.Entry<?, ?> e : m.entrySet()) out.put(String.valueOf(e.getKey()), ordered(e.getValue()));
                return out;
            }
            if (v instanceof List<?> l) {
                List<Object> out = new ArrayList<>();
                for (Object x : l) out.add(ordered(x));
                return out;
            }
            return v;
        }

        static String write(Object v) {
            if (v == null) return "null";
            if (v instanceof String s) return Wire.Json.esc(s);
            if (v instanceof Double d) return d == Math.rint(d) && !Double.isInfinite(d) ? String.valueOf(d.longValue()) : String.valueOf(d);
            if (v instanceof Number || v instanceof Boolean) return String.valueOf(v);
            if (v instanceof Map<?, ?> m) {
                StringBuilder b = new StringBuilder("{");
                int k = 0;
                for (Map.Entry<?, ?> e : m.entrySet()) b.append(k++ > 0 ? "," : "").append(Wire.Json.esc(String.valueOf(e.getKey()))).append(':').append(write(e.getValue()));
                return b.append('}').toString();
            }
            if (v instanceof List<?> l) {
                StringBuilder b = new StringBuilder("[");
                for (int i = 0; i < l.size(); i++) b.append(i > 0 ? "," : "").append(write(l.get(i)));
                return b.append(']').toString();
            }
            return Wire.Json.esc(String.valueOf(v));
        }
    }
}
