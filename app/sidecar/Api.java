// Api.java: the dynamic-proxy helper every bridged Montoya interface is
// built with. A method the bridge implements is looked up by name (and by
// name/argument-count where overloads differ); a default method of the
// interface runs its own body; anything else fails with
// UnsupportedOperationException("<Interface>.<method> is not supported by
// WebProbe"), reported once on the extension's error output.

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

final class Api {
    private Api() {}

    /** One implemented method: the arguments (never null) to the result. */
    interface Impl {
        Object call(Object[] a) throws Throwable;
    }

    /** Unsupported calls already reported (each is logged once). */
    static final Set<String> REPORTED = ConcurrentHashMap.newKeySet();

    static UnsupportedOperationException unsupported(String iface, String method) {
        String msg = iface + "." + method + " is not supported by WebProbe";
        if (REPORTED.add(msg)) Logs.error(msg);
        return new UnsupportedOperationException(msg);
    }

    /** Builder for one proxied object. */
    static final class Obj {
        final Map<String, Impl> impl = new HashMap<>();
        String text;

        /** Implement `name` for every arity. */
        Obj on(String name, Impl f) { impl.put(name, f); return this; }

        /** Implement `name` for one arity only (overloads that differ). */
        Obj on(String name, int arity, Impl f) { impl.put(name + "/" + arity, f); return this; }

        Obj text(String t) { text = t; return this; }

        <T> T as(Class<T> iface) {
            return iface.cast(make(new Class<?>[] { iface }, this));
        }

        Object as(Class<?>... ifaces) {
            return make(ifaces, this);
        }
    }

    static Obj obj() { return new Obj(); }

    static Object make(Class<?>[] ifaces, Obj o) {
        String name = ifaces[0].getSimpleName();
        InvocationHandler h = (proxy, m, args) -> {
            Object[] a = args == null ? new Object[0] : args;
            Impl f = o.impl.get(m.getName() + "/" + a.length);
            if (f == null) f = o.impl.get(m.getName());
            if (f != null) return f.call(a);
            switch (m.getName()) {
                case "toString":
                    if (a.length == 0) return o.text != null ? o.text : name;
                    break;
                case "hashCode":
                    if (a.length == 0) return System.identityHashCode(proxy);
                    break;
                case "equals":
                    if (a.length == 1) return proxy == a[0];
                    break;
                default:
                    break;
            }
            if (m.isDefault()) return InvocationHandler.invokeDefault(proxy, m, args);
            throw unsupported(declaringName(m, name), m.getName());
        };
        return Proxy.newProxyInstance(Api.class.getClassLoader(), ifaces, h);
    }

    private static String declaringName(Method m, String fallback) {
        Class<?> c = m.getDeclaringClass();
        return c == Object.class ? fallback : c.getSimpleName();
    }

    /** A Registration whose deregister() runs `onDeregister`. */
    static Object registration(Runnable onDeregister) {
        boolean[] live = { true };
        return obj()
                .on("isRegistered", a -> live[0])
                .on("deregister", a -> { if (live[0]) { live[0] = false; onDeregister.run(); } return null; })
                .as(burp.api.montoya.core.Registration.class);
    }
}
