// Persist.java: MontoyaApi.persistence(). extensionData() is a
// PersistedObject kept in WebProbe's project file (every change is sent to
// WebProbe, which saves it with the project and hands it back on load);
// preferences() is a per-extension JSON file in WebProbe's user config
// directory (~/.config/webprobe/extension-preferences/<name>.json).

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.persistence.PersistedList;
import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.persistence.Persistence;
import burp.api.montoya.persistence.Preferences;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

final class Persist {
    private Persist() {}

    /** Proxy -> its store (proxies compare by identity). */
    private static final Map<Object, Store> STORES = java.util.Collections.synchronizedMap(new java.util.WeakHashMap<>());

    /** Directory for preferences files (from WebProbe), or null. */
    static Path prefsDir;

    /** One store: kind ("String", "HttpRequestList", "ChildObject" ...) ->
     *  key -> value. Values: String, Boolean, Byte, Short, Integer, Long,
     *  byte[] (ByteArray), HttpRequest, HttpResponse, HttpRequestResponse,
     *  List of those, Store (child object). */
    static final class Store {
        final Map<String, Map<String, Object>> kinds = new TreeMap<>();
        Runnable onChange = () -> {};
        /** The store this one is a child object of: changes bubble up. */
        Store parent;

        void changed() {
            onChange.run();
            if (parent != null) parent.changed();
        }

        Object get(String kind, String key) {
            Map<String, Object> m = kinds.get(kind);
            return m == null ? null : m.get(key);
        }

        void put(String kind, String key, Object v) {
            if (v == null) { delete(kind, key); return; }
            if (v instanceof Store child) child.parent = this;
            kinds.computeIfAbsent(kind, k -> new LinkedHashMap<>()).put(key, v);
            changed();
        }

        void delete(String kind, String key) {
            Map<String, Object> m = kinds.get(kind);
            if (m != null && m.remove(key) != null) changed();
        }

        Set<String> keys(String kind) {
            Map<String, Object> m = kinds.get(kind);
            return m == null ? new LinkedHashSet<>() : new LinkedHashSet<>(m.keySet());
        }
    }

    static final Store ROOT = new Store();
    static final PersistedObject EXTENSION_DATA = object(ROOT);

    /** `getHttpRequestList` -> ("get", "HttpRequestList"). */
    private static String[] split(String method) {
        for (String verb : new String[] { "get", "set", "delete" }) {
            if (method.startsWith(verb) && method.length() > verb.length() && Character.isUpperCase(method.charAt(verb.length()))) {
                return new String[] { verb, method.substring(verb.length()) };
            }
        }
        if (method.endsWith("Keys")) {
            String k = method.substring(0, method.length() - 4);
            return new String[] { "keys", Character.toUpperCase(k.charAt(0)) + k.substring(1) };
        }
        return null;
    }

    /** A PersistedObject (or Preferences) over a store. */
    static PersistedObject object(Store s) {
        return (PersistedObject) store(s, PersistedObject.class);
    }

    static Object store(Store s, Class<?> iface) {
        InvocationHandler h = (proxy, m, args) -> {
            Object[] a = args == null ? new Object[0] : args;
            if (m.getDeclaringClass() == Object.class) {
                switch (m.getName()) {
                    case "hashCode": return System.identityHashCode(proxy);
                    case "equals": return proxy == a[0];
                    default: return iface.getSimpleName() + s.kinds;
                }
            }
            String[] op = split(m.getName());
            if (op == null) throw Api.unsupported(iface.getSimpleName(), m.getName());
            String kind = op[1];
            switch (op[0]) {
                case "get": {
                    Object v = s.get(kind, (String) a[0]);
                    if (v instanceof Store child) return object(child);
                    if (v instanceof byte[] b) return Messages.bytes(b.clone());
                    return v;
                }
                case "set": {
                    Object v = a[1];
                    if (v instanceof PersistedObject po) v = storeOf(po);
                    else if (v instanceof ByteArray ba) v = ba.getBytes();
                    else if (v instanceof List<?> l) v = new ArrayList<>(l);
                    s.put(kind, (String) a[0], v);
                    return null;
                }
                case "delete": s.delete(kind, (String) a[0]); return null;
                default: return s.keys(kind);
            }
        };
        Object o = Proxy.newProxyInstance(Persist.class.getClassLoader(), new Class<?>[] { iface }, h);
        STORES.put(o, s);
        return o;
    }


    /** The store behind a PersistedObject made here. */
    static Store storeOf(PersistedObject po) {
        Store s = STORES.get(po);
        if (s == null) throw new IllegalArgumentException("not a PersistedObject made by WebProbe (use PersistedObject.persistedObject())");
        return s;
    }

    static Persistence persistence() {
        return Api.obj()
                .on("extensionData", a -> EXTENSION_DATA)
                .on("preferences", a -> preferences())
                .as(Persistence.class);
    }

    // ------------------------------------------------------------ lists

    /** A PersistedList: an ArrayList behind the List interface. */
    @SuppressWarnings("unchecked")
    static <T> PersistedList<T> list() {
        List<T> backing = new ArrayList<>();
        InvocationHandler h = (proxy, m, args) -> {
            if (m.getName().equals("equals") && args != null && args.length == 1) return proxy == args[0] || backing.equals(args[0]);
            if (m.getName().equals("hashCode") && args == null) return backing.hashCode();
            try {
                return m.invoke(backing, args);
            } catch (java.lang.reflect.InvocationTargetException e) {
                throw e.getCause();
            }
        };
        return (PersistedList<T>) Proxy.newProxyInstance(Persist.class.getClassLoader(), new Class<?>[] { PersistedList.class }, h);
    }

    // ------------------------------------------------------------ JSON for WebProbe's project file

    static String toJson(Store s) {
        StringBuilder b = new StringBuilder("{");
        int k = 0;
        for (Map.Entry<String, Map<String, Object>> kind : s.kinds.entrySet()) {
            if (kind.getValue().isEmpty()) continue;
            b.append(k++ > 0 ? "," : "").append(Wire.Json.esc(kind.getKey())).append(":{");
            int j = 0;
            for (Map.Entry<String, Object> e : kind.getValue().entrySet()) {
                b.append(j++ > 0 ? "," : "").append(Wire.Json.esc(e.getKey())).append(':').append(value(e.getValue()));
            }
            b.append('}');
        }
        return b.append('}').toString();
    }

    private static String value(Object v) {
        if (v instanceof Store s) return toJson(s);
        if (v instanceof String str) return Wire.Json.esc(str);
        if (v instanceof Boolean || v instanceof Number) return String.valueOf(v);
        if (v instanceof byte[] b) return Wire.Json.esc(Wire.b64(b));
        if (v instanceof ByteArray ba) return Wire.Json.esc(Wire.b64(ba.getBytes()));
        if (v instanceof HttpRequest q) return message(q, null);
        if (v instanceof HttpResponse r) return Wire.Json.esc(Wire.b64(Messages.rawOf(r)));
        if (v instanceof HttpRequestResponse rr) return message(rr.request(), rr.response());
        if (v instanceof List<?> l) {
            StringBuilder b = new StringBuilder("[");
            for (int i = 0; i < l.size(); i++) b.append(i > 0 ? "," : "").append(value(l.get(i)));
            return b.append(']').toString();
        }
        return "null";
    }

    private static String message(HttpRequest q, HttpResponse r) {
        HttpService svc = q.httpService();
        return "{\"request\":" + Wire.Json.esc(Wire.b64(Messages.rawOf(q))) + ",\"host\":" + Wire.Json.esc(svc.host()) + ",\"port\":" + svc.port()
                + ",\"secure\":" + svc.secure() + (r == null ? "" : ",\"response\":" + Wire.Json.esc(Wire.b64(Messages.rawOf(r)))) + "}";
    }

    /** Replace a store's contents with saved JSON (the same store object, so
     *  references the extension holds see the restored data). */
    @SuppressWarnings("unchecked")
    static void fromJson(Store s, Map<String, Object> json) {
        s.kinds.clear();
        if (json == null) return;
        for (Map.Entry<String, Object> kind : json.entrySet()) {
            Map<String, Object> vals = new LinkedHashMap<>();
            for (Map.Entry<String, Object> e : ((Map<String, Object>) kind.getValue()).entrySet()) {
                Object v = restore(kind.getKey(), e.getValue());
                if (v instanceof Store child) child.parent = s;
                vals.put(e.getKey(), v);
            }
            s.kinds.put(kind.getKey(), vals);
        }
    }

    @SuppressWarnings("unchecked")
    private static Object restore(String kind, Object v) {
        if (kind.endsWith("List") && v instanceof List<?> l) {
            PersistedList<Object> out = list();
            String one = kind.substring(0, kind.length() - 4);
            for (Object x : l) out.add(restore(one, x));
            return out;
        }
        switch (kind) {
            case "ChildObject": { Store c = new Store(); fromJson(c, (Map<String, Object>) v); return c; }
            case "String": case "Boolean": return v;
            case "Byte": return ((Number) v).byteValue();
            case "Short": return ((Number) v).shortValue();
            case "Integer": return ((Number) v).intValue();
            case "Long": return ((Number) v).longValue();
            case "ByteArray": return Wire.unb64((String) v);
            case "HttpResponse": return Messages.response(Wire.unb64((String) v), null, HttpResponse.class);
            case "HttpRequest": case "HttpRequestResponse": {
                Map<String, Object> m = (Map<String, Object>) v;
                HttpRequestResponse rr = Ui.pair(m);
                return kind.equals("HttpRequest") ? rr.request() : rr;
            }
            default: return v;
        }
    }

    // ------------------------------------------------------------ preferences

    private static Preferences prefs;

    static synchronized Preferences preferences() {
        if (prefs != null) return prefs;
        Store s = new Store();
        Path file = prefsFile();
        if (file != null && Files.isRegularFile(file)) {
            try {
                @SuppressWarnings("unchecked")
                Map<String, Object> json = (Map<String, Object>) Wire.Json.parse(Files.readString(file, StandardCharsets.UTF_8));
                fromJson(s, json);
            } catch (Exception e) {
                Logs.error("[bridge] could not read preferences " + file + ": " + e);
            }
        }
        s.onChange = () -> {
            if (file == null) return;
            try {
                Files.createDirectories(file.getParent());
                Files.writeString(file, toJson(s), StandardCharsets.UTF_8);
            } catch (Exception e) {
                Logs.error("[bridge] could not save preferences " + file + ": " + e);
            }
        };
        prefs = (Preferences) store(s, Preferences.class);
        return prefs;
    }

    /** Per extension: the name it gave itself, else its jar's file name. */
    private static Path prefsFile() {
        if (prefsDir == null) return null;
        String key = Bridge.name.isEmpty() ? Path.of(Bridge.jarPath).getFileName().toString() : Bridge.name;
        return prefsDir.resolve(key.replaceAll("[^A-Za-z0-9._ -]", "_") + ".json");
    }
}
