// Messages.java: the Montoya HTTP value types (HttpRequest, HttpResponse,
// HttpHeader, HttpService, ByteArray, parameters, Annotations, ToolSource)
// over raw message bytes. Every with* method returns a new message with the
// edit applied to the bytes; withBody keeps Content-Length right.

import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.core.ToolSource;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

final class Messages {
    private Messages() {}

    static final java.nio.charset.Charset L1 = StandardCharsets.ISO_8859_1;

    // ------------------------------------------------------------ service

    record Svc(String host, int port, boolean secure) {
        String origin() {
            boolean dflt = port == 0 || port == (secure ? 443 : 80);
            return (secure ? "https://" : "http://") + host + (dflt ? "" : ":" + port);
        }
    }

    static HttpService service(Svc s) {
        return Api.obj()
                .on("host", a -> s.host())
                .on("port", a -> s.port())
                .on("secure", a -> s.secure())
                .on("ipAddress", a -> {
                    try { return java.net.InetAddress.getByName(s.host()).getHostAddress(); }
                    catch (Exception e) { throw new IllegalStateException("cannot resolve " + s.host(), e); }
                })
                .text(s.origin())
                .as(HttpService.class);
    }

    static Svc svcOf(HttpService h) {
        return h == null ? new Svc("", 80, false) : new Svc(h.host(), h.port(), h.secure());
    }

    /** "https://host:8443" (or a bare host) as a service. */
    static Svc svcFromUrl(String url) {
        String u = url.trim();
        boolean secure = u.toLowerCase(Locale.ROOT).startsWith("https://");
        int i = u.indexOf("://");
        String rest = i >= 0 ? u.substring(i + 3) : u;
        int slash = rest.indexOf('/');
        String auth = slash >= 0 ? rest.substring(0, slash) : rest;
        int colon = auth.lastIndexOf(':');
        if (colon > 0 && !auth.endsWith("]")) {
            return new Svc(auth.substring(0, colon), Integer.parseInt(auth.substring(colon + 1)), secure);
        }
        return new Svc(auth, secure ? 443 : 80, secure);
    }

    // ------------------------------------------------------------ byte arrays and headers

    static ByteArray bytes(byte[] init) {
        byte[][] d = { init };
        Api.Obj o = Api.obj();
        o.on("getByte", a -> d[0][((Number) a[0]).intValue()])
         .on("setByte", a -> { d[0][((Number) a[0]).intValue()] = ((Number) a[1]).byteValue(); return null; })
         .on("length", a -> d[0].length)
         .on("getBytes", a -> d[0].clone())
         .on("copy", a -> bytes(d[0].clone()))
         .on("copyToTempFile", a -> bytes(d[0].clone()))
         .on("subArray", 2, a -> bytes(Arrays.copyOfRange(d[0], ((Number) a[0]).intValue(), ((Number) a[1]).intValue())))
         .on("subArray", 1, a -> {
             burp.api.montoya.core.Range r = (burp.api.montoya.core.Range) a[0];
             return bytes(Arrays.copyOfRange(d[0], r.startIndexInclusive(), r.endIndexExclusive()));
         })
         .on("indexOf", a -> indexOf(d[0], a))
         .on("countMatches", a -> {
             byte[] n = needle(a[0]);
             boolean cs = a.length < 2 || !(a[1] instanceof Boolean b) || b;
             int count = 0, from = 0, at;
             while (n.length > 0 && (at = find(d[0], n, cs, from, d[0].length)) >= 0) { count++; from = at + n.length; }
             return count;
         })
         .on("withAppended", a -> {
             byte[] more = a[0] instanceof ByteArray b ? b.getBytes() : a[0] instanceof String s ? s.getBytes(L1) : (byte[]) a[0];
             byte[] out = Arrays.copyOf(d[0], d[0].length + more.length);
             System.arraycopy(more, 0, out, d[0].length, more.length);
             return bytes(out);
         })
         .on("iterator", a -> {
             List<Byte> l = new ArrayList<>();
             for (byte b : d[0]) l.add(b);
             return l.iterator();
         })
         .on("toString", 0, a -> new String(d[0], L1));
        return o.as(ByteArray.class);
    }

    private static byte[] needle(Object o) {
        return o instanceof ByteArray b ? b.getBytes() : String.valueOf(o).getBytes(L1);
    }

    private static Object indexOf(byte[] hay, Object[] a) {
        if (a[0] instanceof Pattern p) {
            String s = new String(hay, L1);
            java.util.regex.Matcher m = p.matcher(s);
            if (a.length == 3) m.region(((Number) a[1]).intValue(), ((Number) a[2]).intValue());
            return m.find() ? m.start() : -1;
        }
        byte[] n = needle(a[0]);
        boolean cs = a.length < 2 || !(a[1] instanceof Boolean) || (Boolean) a[1];
        int from = a.length >= 4 ? ((Number) a[2]).intValue() : 0;
        int to = a.length >= 4 ? ((Number) a[3]).intValue() : hay.length;
        return find(hay, n, cs, from, to);
    }

    static int find(byte[] hay, byte[] n, boolean caseSensitive, int from, int to) {
        outer:
        for (int i = Math.max(0, from); i + n.length <= Math.min(to, hay.length); i++) {
            for (int k = 0; k < n.length; k++) {
                byte x = hay[i + k], y = n[k];
                if (x != y && (caseSensitive || Character.toLowerCase((char) (x & 0xff)) != Character.toLowerCase((char) (y & 0xff)))) continue outer;
            }
            return i;
        }
        return -1;
    }

    static HttpHeader header(String name, String value) {
        return Api.obj()
                .on("name", a -> name)
                .on("value", a -> value)
                .on("equals", a -> a[0] instanceof HttpHeader h && h.name().equals(name) && h.value().equals(value))
                .on("hashCode", a -> (name + ": " + value).hashCode())
                .text(name + ": " + value)
                .as(HttpHeader.class);
    }

    /** "Name: value" as a header. */
    static HttpHeader header(String line) {
        int c = line.indexOf(':');
        return c < 0 ? header(line.trim(), "") : header(line.substring(0, c).trim(), line.substring(c + 1).trim());
    }

    // ------------------------------------------------------------ raw messages

    /** A parsed HTTP message: first line, header lines, body. */
    static final class Raw {
        String first;
        final List<String[]> headers = new ArrayList<>();
        byte[] body;

        static Raw parse(byte[] b) {
            Raw r = new Raw();
            int end = -1, sep = 0;
            for (int i = 0; i + 1 < b.length; i++) {
                if (b[i] == '\n' && b[i + 1] == '\n') { end = i; sep = 2; break; }
                if (i + 3 < b.length && b[i] == '\r' && b[i + 1] == '\n' && b[i + 2] == '\r' && b[i + 3] == '\n') { end = i; sep = 4; break; }
            }
            String head = new String(b, 0, end < 0 ? b.length : end, L1);
            r.body = end < 0 ? new byte[0] : Arrays.copyOfRange(b, end + sep, b.length);
            String[] lines = head.split("\r?\n", -1);
            r.first = lines.length > 0 ? lines[0] : "";
            for (int i = 1; i < lines.length; i++) {
                String l = lines[i];
                if (l.isEmpty()) continue;
                int c = l.indexOf(':');
                r.headers.add(c < 0 ? new String[] { l, "" } : new String[] { l.substring(0, c), l.substring(c + 1).trim() });
            }
            return r;
        }

        byte[] build() {
            StringBuilder s = new StringBuilder(first);
            for (String[] h : headers) s.append("\r\n").append(h[0]).append(": ").append(h[1]);
            s.append("\r\n\r\n");
            byte[] head = s.toString().getBytes(L1);
            byte[] out = Arrays.copyOf(head, head.length + body.length);
            System.arraycopy(body, 0, out, head.length, body.length);
            return out;
        }

        int bodyOffset(byte[] b) { return b.length - body.length; }

        String value(String name) {
            for (String[] h : headers) if (h[0].equalsIgnoreCase(name)) return h[1];
            return null;
        }

        void set(String name, String value, boolean addIfMissing) {
            boolean found = false;
            for (String[] h : headers) if (h[0].equalsIgnoreCase(name)) { h[1] = value; found = true; }
            if (!found && addIfMissing) headers.add(new String[] { name, value });
        }

        void remove(String name) { headers.removeIf(h -> h[0].equalsIgnoreCase(name)); }

        /** A new body, with Content-Length following it (added unless the
         *  message is chunked or had neither a length nor a body). */
        void setBody(byte[] nb) {
            boolean chunked = value("Transfer-Encoding") != null && value("Transfer-Encoding").toLowerCase(Locale.ROOT).contains("chunked");
            if (chunked) remove("Transfer-Encoding");
            if (value("Content-Length") != null || nb.length > 0 || chunked) set("Content-Length", String.valueOf(nb.length), true);
            body = nb;
        }

        List<HttpHeader> headerList() {
            List<HttpHeader> l = new ArrayList<>();
            for (String[] h : headers) l.add(header(h[0], h[1]));
            return l;
        }
    }

    @SuppressWarnings("unchecked")
    static List<Object> many(Object[] a) {
        if (a.length == 1 && a[0] instanceof List<?> l) return (List<Object>) l;
        if (a.length == 1 && a[0] instanceof Object[] arr) return Arrays.asList(arr);
        return Arrays.asList(a);
    }

    static String[] headerArgs(Object[] a) {
        if (a.length >= 2) return new String[] { String.valueOf(a[0]), String.valueOf(a[1]) };
        HttpHeader h = (HttpHeader) a[0];
        return new String[] { h.name(), h.value() };
    }

    static byte[] bodyArg(Object o) {
        return o instanceof ByteArray b ? b.getBytes() : String.valueOf(o).getBytes(L1);
    }

    /** The message methods requests and responses share. */
    static void common(Api.Obj o, byte[] raw, Raw r) {
        o.on("headers", a -> r.headerList())
         .on("header", a -> { String v = r.value(String.valueOf(a[0])); return v == null ? null : header(headerName(r, String.valueOf(a[0])), v); })
         .on("headerValue", a -> r.value(String.valueOf(a[0])))
         .on("hasHeader", 1, a -> a[0] instanceof HttpHeader h ? h.value().equals(r.value(h.name())) : r.value(String.valueOf(a[0])) != null)
         .on("hasHeader", 2, a -> String.valueOf(a[1]).equals(r.value(String.valueOf(a[0]))))
         .on("httpVersion", a -> version(r))
         .on("bodyOffset", a -> r.bodyOffset(raw))
         .on("body", a -> bytes(r.body.clone()))
         .on("bodyToString", a -> new String(r.body, L1))
         .on("markers", a -> List.of())
         .on("toByteArray", a -> bytes(raw.clone()))
         .on("contains", a -> a[0] instanceof Pattern p ? p.matcher(new String(raw, L1)).find()
                 : find(raw, String.valueOf(a[0]).getBytes(L1), (Boolean) a[1], 0, raw.length) >= 0)
         .on("toString", 0, a -> new String(raw, L1));
    }

    private static String headerName(Raw r, String want) {
        for (String[] h : r.headers) if (h[0].equalsIgnoreCase(want)) return h[0];
        return want;
    }

    private static String version(Raw r) {
        String[] p = r.first.split(" ");
        if (r.first.startsWith("HTTP/")) return p[0];
        return p.length >= 3 ? p[2] : "HTTP/1.1";
    }

    // ------------------------------------------------------------ requests

    /** An HttpRequest (or a subtype: InterceptedRequest,
     *  HttpRequestToBeSent) over `raw`; `extra` adds the subtype's methods. */
    static Object request(byte[] raw, Svc svc, Api.Obj extra, Class<?> iface) {
        Raw r = Raw.parse(raw);
        Api.Obj o = Api.obj();
        common(o, raw, r);
        String[] fl = r.first.split(" ", 3);
        String method = fl.length > 0 ? fl[0] : "";
        String target = fl.length > 1 ? fl[1] : "/";
        String path = target.contains("://") ? pathOf(target) : target;
        int q = path.indexOf('?');
        o.on("httpService", a -> service(svc))
         .on("url", a -> target.contains("://") ? target : svc.origin() + path)
         .on("method", a -> method)
         .on("path", a -> path)
         .on("query", a -> q < 0 ? "" : path.substring(q + 1))
         .on("pathWithoutQuery", a -> q < 0 ? path : path.substring(0, q))
         .on("fileExtension", a -> {
             String p = q < 0 ? path : path.substring(0, q);
             String last = p.substring(p.lastIndexOf('/') + 1);
             int dot = last.lastIndexOf('.');
             return dot < 0 ? "" : last.substring(dot + 1);
         })
         .on("contentType", a -> contentType(r))
         .on("parameters", 0, a -> params(r, path, null))
         .on("parameters", 1, a -> params(r, path, (HttpParameterType) a[0]))
         .on("hasParameters", 0, a -> !params(r, path, null).isEmpty())
         .on("hasParameters", 1, a -> !params(r, path, (HttpParameterType) a[0]).isEmpty())
         .on("parameter", 1, a -> first(params(r, path, null), String.valueOf(a[0])))
         .on("parameter", 2, a -> first(params(r, path, (HttpParameterType) a[1]), String.valueOf(a[0])))
         .on("parameterValue", 1, a -> { ParsedHttpParameter p = first(params(r, path, null), String.valueOf(a[0])); return p == null ? null : p.value(); })
         .on("parameterValue", 2, a -> { ParsedHttpParameter p = first(params(r, path, (HttpParameterType) a[1]), String.valueOf(a[0])); return p == null ? null : p.value(); })
         .on("hasParameter", 2, a -> first(params(r, path, (HttpParameterType) a[1]), String.valueOf(a[0])) != null)
         .on("hasParameter", 1, a -> {
             burp.api.montoya.http.message.params.HttpParameter want = (burp.api.montoya.http.message.params.HttpParameter) a[0];
             ParsedHttpParameter p = first(params(r, path, want.type()), want.name());
             return p != null && p.value().equals(want.value());
         })
         .on("copyToTempFile", a -> request(raw, svc, null, HttpRequest.class))
         .on("withService", a -> request(raw, svcOf((HttpService) a[0]), null, HttpRequest.class))
         .on("withPath", a -> withFirst(r, svc, method + " " + a[0] + " " + version(r)))
         .on("withMethod", a -> withFirst(r, svc, a[0] + " " + target + " " + version(r)))
         .on("withHeader", a -> editReq(r, svc, x -> { String[] h = headerArgs(a); x.set(h[0], h[1], true); }))
         .on("withAddedHeader", a -> editReq(r, svc, x -> x.headers.add(headerArgs(a))))
         .on("withAddedHeaders", a -> editReq(r, svc, x -> { for (Object h : many(a)) x.headers.add(headerArgs(new Object[] { h })); }))
         .on("withUpdatedHeader", a -> editReq(r, svc, x -> { String[] h = headerArgs(a); x.set(h[0], h[1], false); }))
         .on("withUpdatedHeaders", a -> editReq(r, svc, x -> { for (Object h : many(a)) { String[] p = headerArgs(new Object[] { h }); x.set(p[0], p[1], false); } }))
         .on("withRemovedHeader", a -> editReq(r, svc, x -> x.remove(a[0] instanceof HttpHeader h ? h.name() : String.valueOf(a[0]))))
         .on("withRemovedHeaders", a -> editReq(r, svc, x -> { for (Object h : many(a)) x.remove(h instanceof HttpHeader hh ? hh.name() : String.valueOf(h)); }))
         .on("withBody", a -> editReq(r, svc, x -> x.setBody(bodyArg(a[0]))))
         .on("withParameter", a -> editReq(r, svc, x -> editParams(x, many(a), 's')))
         .on("withAddedParameters", a -> editReq(r, svc, x -> editParams(x, many(a), 'a')))
         .on("withUpdatedParameters", a -> editReq(r, svc, x -> editParams(x, many(a), 'u')))
         .on("withRemovedParameters", a -> editReq(r, svc, x -> editParams(x, many(a), 'r')))
         .on("withMarkers", a -> request(raw, svc, null, HttpRequest.class))
         .text(new String(raw, L1));
        if (extra != null) o.impl.putAll(extra.impl);
        return Api.make(new Class<?>[] { iface }, o);
    }

    private static String pathOf(String absolute) {
        int i = absolute.indexOf("://");
        int slash = absolute.indexOf('/', i + 3);
        return slash < 0 ? "/" : absolute.substring(slash);
    }

    interface Edit { void apply(Raw r); }

    private static Raw copy(Raw r) {
        Raw c = new Raw();
        c.first = r.first;
        for (String[] h : r.headers) c.headers.add(new String[] { h[0], h[1] });
        c.body = r.body.clone();
        return c;
    }

    private static Object editReq(Raw r, Svc svc, Edit e) {
        Raw c = copy(r);
        e.apply(c);
        return request(c.build(), svc, null, HttpRequest.class);
    }

    private static Object withFirst(Raw r, Svc svc, String first) {
        Raw c = copy(r);
        c.first = first;
        return request(c.build(), svc, null, HttpRequest.class);
    }

    private static Object contentType(Raw r) {
        String ct = r.value("Content-Type");
        String name;
        if (ct == null) name = "NONE";
        else {
            String l = ct.toLowerCase(Locale.ROOT);
            name = l.contains("x-www-form-urlencoded") ? "URL_ENCODED" : l.contains("multipart") ? "MULTIPART"
                    : l.contains("json") ? "JSON" : l.contains("xml") ? "XML" : l.contains("amf") ? "AMF" : "UNKNOWN";
        }
        return Enum.valueOf(burp.api.montoya.http.message.ContentType.class, name);
    }

    private static ParsedHttpParameter first(List<ParsedHttpParameter> ps, String name) {
        for (ParsedHttpParameter p : ps) if (p.name().equals(name)) return p;
        return null;
    }

    /** URL, form-body and cookie parameters (names and values as sent). */
    static List<ParsedHttpParameter> params(Raw r, String path, HttpParameterType only) {
        List<ParsedHttpParameter> out = new ArrayList<>();
        int q = path.indexOf('?');
        if (q >= 0) pairs(path.substring(q + 1), "&", HttpParameterType.URL, only, out);
        String ct = r.value("Content-Type");
        if (ct != null && ct.toLowerCase(Locale.ROOT).contains("x-www-form-urlencoded")) {
            pairs(new String(r.body, L1), "&", HttpParameterType.BODY, only, out);
        }
        String cookie = r.value("Cookie");
        if (cookie != null) pairs(cookie, ";", HttpParameterType.COOKIE, only, out);
        return out;
    }

    /** An HttpParameter value (HttpParameter.urlParameter(..) etc.). */
    static burp.api.montoya.http.message.params.HttpParameter parameter(String name, String value, HttpParameterType type) {
        return Api.obj()
                .on("name", a -> name)
                .on("value", a -> value)
                .on("type", a -> type)
                .text(name + "=" + value)
                .as(burp.api.montoya.http.message.params.HttpParameter.class);
    }

    /** Add, update or remove URL, body and cookie parameters (others are
     *  not supported). `mode`: 'a' add, 'u' update, 's' set (update or
     *  add), 'r' remove. */
    static void editParams(Raw r, List<Object> params, char mode) {
        String[] fl = r.first.split(" ", 3);
        String target = fl.length > 1 ? fl[1] : "/";
        int q = target.indexOf('?');
        List<String[]> url = split(q < 0 ? "" : target.substring(q + 1), "&");
        boolean form = r.value("Content-Type") != null && r.value("Content-Type").toLowerCase(Locale.ROOT).contains("x-www-form-urlencoded");
        List<String[]> body = split(new String(r.body, L1), "&");
        List<String[]> cookies = split(r.value("Cookie") == null ? "" : r.value("Cookie"), ";");
        boolean bodyTouched = false, cookieTouched = false, urlTouched = false;
        for (Object o : params) {
            burp.api.montoya.http.message.params.HttpParameter p = (burp.api.montoya.http.message.params.HttpParameter) o;
            List<String[]> list;
            switch (p.type()) {
                case URL: list = url; urlTouched = true; break;
                case BODY: list = body; bodyTouched = true; break;
                case COOKIE: list = cookies; cookieTouched = true; break;
                default: throw Api.unsupported("HttpRequest", "withParameter(" + p.type() + ")");
            }
            boolean found = false;
            for (java.util.Iterator<String[]> it = list.iterator(); it.hasNext();) {
                String[] kv = it.next();
                if (!kv[0].equals(p.name())) continue;
                found = true;
                if (mode == 'r') it.remove(); else if (mode != 'a') kv[1] = p.value();
            }
            if (mode == 'a' || (mode == 's' && !found)) list.add(new String[] { p.name(), p.value() });
        }
        if (urlTouched) {
            String base = q < 0 ? target : target.substring(0, q);
            String qs = join(url, "&");
            r.first = fl[0] + " " + base + (qs.isEmpty() ? "" : "?" + qs) + (fl.length > 2 ? " " + fl[2] : "");
        }
        if (bodyTouched) {
            if (!form) r.set("Content-Type", "application/x-www-form-urlencoded", true);
            r.setBody(join(body, "&").getBytes(L1));
        }
        if (cookieTouched) {
            if (cookies.isEmpty()) r.remove("Cookie"); else r.set("Cookie", join(cookies, "; "), true);
        }
    }

    private static List<String[]> split(String s, String sep) {
        List<String[]> out = new ArrayList<>();
        for (String p : s.split(sep)) {
            p = p.trim();
            if (p.isEmpty()) continue;
            int e = p.indexOf('=');
            out.add(e < 0 ? new String[] { p, "" } : new String[] { p.substring(0, e), p.substring(e + 1) });
        }
        return out;
    }

    private static String join(List<String[]> kv, String sep) {
        StringBuilder b = new StringBuilder();
        for (String[] p : kv) b.append(b.length() > 0 ? sep : "").append(p[0]).append('=').append(p[1]);
        return b.toString();
    }

    private static void pairs(String s, String sep, HttpParameterType type, HttpParameterType only, List<ParsedHttpParameter> out) {
        if (only != null && only != type) return;
        for (String p : s.split(sep)) {
            p = p.trim();
            if (p.isEmpty()) continue;
            int e = p.indexOf('=');
            String n = e < 0 ? p : p.substring(0, e), v = e < 0 ? "" : p.substring(e + 1);
            out.add(Api.obj()
                    .on("type", a -> type)
                    .on("name", a -> n)
                    .on("value", a -> v)
                    .text(n + "=" + v)
                    .as(ParsedHttpParameter.class));
        }
    }

    // ------------------------------------------------------------ responses

    static Object response(byte[] raw, Api.Obj extra, Class<?> iface) {
        Raw r = Raw.parse(raw);
        Api.Obj o = Api.obj();
        common(o, raw, r);
        String[] fl = r.first.split(" ", 3);
        short status = (short) (fl.length > 1 ? parseInt(fl[1], 200) : 200);
        String reason = fl.length > 2 ? fl[2] : "";
        o.on("statusCode", a -> status)
         .on("reasonPhrase", a -> reason)
         .on("hasCookie", a -> {
             String name = a[0] instanceof burp.api.montoya.http.message.Cookie c ? c.name() : (String) a[0];
             for (String[] header : r.headers) {
                 if (!header[0].equalsIgnoreCase("Set-Cookie")) continue;
                 try {
                     for (java.net.HttpCookie cookie : java.net.HttpCookie.parse(header[1])) {
                         if (cookie.getName().equals(name) && (!(a[0] instanceof burp.api.montoya.http.message.Cookie c)
                                 || cookie.getValue().equals(c.value())
                                 && java.util.Objects.equals(cookie.getDomain(), c.domain())
                                 && java.util.Objects.equals(cookie.getPath(), c.path()))) return true;
                     }
                 } catch (IllegalArgumentException invalid) { /* Ignore malformed Set-Cookie, not other headers. */ }
             }
             return false;
         })
         .on("isStatusCodeClass", a -> {
             String n = ((Enum<?>) a[0]).name();
             return n.contains("_" + (status / 100) + "XX");
         })
         .on("copyToTempFile", a -> response(raw, null, HttpResponse.class))
         .on("withStatusCode", a -> editResp(r, x -> x.first = version(r) + " " + ((Number) a[0]).intValue() + " " + reason))
         .on("withReasonPhrase", a -> editResp(r, x -> x.first = version(r) + " " + status + " " + a[0]))
         .on("withHttpVersion", a -> editResp(r, x -> x.first = a[0] + " " + status + " " + reason))
         .on("withAddedHeader", a -> editResp(r, x -> x.headers.add(headerArgs(a))))
         .on("withAddedHeaders", a -> editResp(r, x -> { for (Object h : many(a)) x.headers.add(headerArgs(new Object[] { h })); }))
         .on("withUpdatedHeader", a -> editResp(r, x -> { String[] h = headerArgs(a); x.set(h[0], h[1], false); }))
         .on("withUpdatedHeaders", a -> editResp(r, x -> { for (Object h : many(a)) { String[] p = headerArgs(new Object[] { h }); x.set(p[0], p[1], false); } }))
         .on("withRemovedHeader", a -> editResp(r, x -> x.remove(a[0] instanceof HttpHeader h ? h.name() : String.valueOf(a[0]))))
         .on("withRemovedHeaders", a -> editResp(r, x -> { for (Object h : many(a)) x.remove(h instanceof HttpHeader hh ? hh.name() : String.valueOf(h)); }))
         .on("withBody", a -> editResp(r, x -> x.setBody(bodyArg(a[0]))))
         .on("withMarkers", a -> response(raw, null, HttpResponse.class))
         .text(new String(raw, L1));
        if (extra != null) o.impl.putAll(extra.impl);
        return Api.make(new Class<?>[] { iface }, o);
    }

    private static int parseInt(String s, int dflt) {
        try { return Integer.parseInt(s.trim()); } catch (NumberFormatException e) { return dflt; }
    }

    private static Object editResp(Raw r, Edit e) {
        Raw c = copy(r);
        e.apply(c);
        return response(c.build(), null, HttpResponse.class);
    }

    /** The bytes of any HttpRequest / HttpResponse (ours or another
     *  implementation's). */
    static byte[] rawOf(Object message) {
        if (message instanceof HttpRequest q) return q.toByteArray().getBytes();
        if (message instanceof HttpResponse p) return p.toByteArray().getBytes();
        return null;
    }

    static HttpRequestResponse requestResponse(HttpRequest req, HttpResponse resp, Annotations ann) {
        return Api.obj()
                .on("request", a -> req)
                .on("response", a -> resp)
                .on("hasResponse", a -> resp != null)
                .on("httpService", a -> req.httpService())
                .on("annotations", a -> ann)
                .on("url", a -> req.url())
                .on("statusCode", a -> resp == null ? (short) 0 : resp.statusCode())
                .on("timingData", a -> java.util.Optional.empty())
                .on("requestMarkers", a -> List.of())
                .on("responseMarkers", a -> List.of())
                .on("withAnnotations", a -> requestResponse(req, resp, (Annotations) a[0]))
                .as(HttpRequestResponse.class);
    }

    // ------------------------------------------------------------ annotations and tools

    /** Mutable notes and highlight (Montoya Annotations). */
    static Annotations annotations(String notes, HighlightColor color) {
        String[] n = { notes == null ? "" : notes };
        HighlightColor[] c = { color == null ? HighlightColor.NONE : color };
        return Api.obj()
                .on("notes", a -> n[0])
                .on("hasNotes", a -> !n[0].isEmpty())
                .on("setNotes", a -> { n[0] = a[0] == null ? "" : String.valueOf(a[0]); return null; })
                .on("highlightColor", a -> c[0])
                .on("hasHighlightColor", a -> c[0] != HighlightColor.NONE)
                .on("setHighlightColor", a -> { c[0] = a[0] == null ? HighlightColor.NONE : (HighlightColor) a[0]; return null; })
                .on("withNotes", a -> annotations(String.valueOf(a[0]), c[0]))
                .on("withHighlightColor", a -> annotations(n[0], (HighlightColor) a[0]))
                .as(Annotations.class);
    }

    static ToolSource tool(String name) {
        ToolType t;
        try { t = ToolType.valueOf(name.toUpperCase(Locale.ROOT)); } catch (Exception e) { t = ToolType.EXTENSIONS; }
        ToolType type = t;
        return Api.obj()
                .on("toolType", a -> type)
                .on("isFromTool", a -> {
                    for (Object x : many(a)) if (x == type) return true;
                    return false;
                })
                .text(type.toolName())
                .as(ToolSource.class);
    }
}
