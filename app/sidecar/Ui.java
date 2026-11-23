// Ui.java: MontoyaApi.userInterface(). The extension's Swing components live
// in this JVM: its suite tabs (and the editors it provides) are shown in one
// window per extension, titled "<name> - WebProbe", a JTabbedPane when there
// are several. WebProbe cannot embed Swing in its own (egui) window; its
// Extensions tab lists the tabs and opens this window. Context-menu items
// are flattened into labels WebProbe shows in its own menus; choosing one
// runs the item's action here. Without a display (headless) nothing is
// shown, registration still succeeds, and WebProbe says why.

import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.core.Range;
import burp.api.montoya.core.ToolSource;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.Theme;
import burp.api.montoya.ui.UserInterface;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.InvocationType;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.EditorMode;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedEditor;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import burp.api.montoya.ui.editor.extension.HttpRequestEditorProvider;
import burp.api.montoya.ui.editor.extension.HttpResponseEditorProvider;

import java.awt.Color;
import java.awt.Component;
import java.awt.Font;
import java.awt.GraphicsEnvironment;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;
import javax.swing.AbstractButton;
import javax.swing.JComponent;
import javax.swing.JFrame;
import javax.swing.JMenu;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;
import javax.swing.WindowConstants;

final class Ui {
    private Ui() {}

    static final boolean HEADLESS = GraphicsEnvironment.isHeadless();
    /** Loaded at WebProbe start: the window opens on demand only. */
    static boolean startup;

    /** Suite tabs and editor tabs, by title, in registration order. */
    static final Map<String, Component> TABS = new LinkedHashMap<>();
    static final List<ContextMenuItemsProvider> MENUS = new CopyOnWriteArrayList<>();
    static final List<HttpRequestEditorProvider> REQUEST_EDITORS = new CopyOnWriteArrayList<>();
    static final List<HttpResponseEditorProvider> RESPONSE_EDITORS = new CopyOnWriteArrayList<>();
    static final List<Object> WS_EDITORS = new CopyOnWriteArrayList<>();
    static JFrame frame;
    static JTabbedPane pane;

    static void onEdt(Runnable r) {
        if (SwingUtilities.isEventDispatchThread()) { r.run(); return; }
        try { SwingUtilities.invokeAndWait(r); } catch (Exception e) { throw new RuntimeException(e.getCause() != null ? e.getCause() : e); }
    }

    static String title() {
        return (Bridge.name.isEmpty() ? "Extension" : Bridge.name) + " - WebProbe";
    }

    /** What WebProbe's Extensions tab shows about this extension's UI. */
    static void pushState() {
        StringBuilder s = new StringBuilder("{\"type\":\"ui\",\"tabs\":[");
        int k = 0;
        for (String t : TABS.keySet()) s.append(k++ > 0 ? "," : "").append(Wire.Json.esc(t));
        s.append("],\"headless\":").append(HEADLESS)
         .append(",\"visible\":").append(frame != null && frame.isVisible())
         .append(",\"menus\":").append(MENUS.size())
         .append(",\"requestEditors\":").append(REQUEST_EDITORS.size())
         .append(",\"responseEditors\":").append(RESPONSE_EDITORS.size())
         .append(",\"activeChecks\":").append(Engine.activeCount())
         .append(",\"passiveChecks\":").append(Engine.passiveCount())
         .append(",\"wsHandlers\":").append(Engine.wsCount());
        for (String key : new String[] { "generators", "processors", "sessionActions" }) {
            s.append(",\"").append(key).append("\":[");
            int j = 0;
            List<?> l = key.equals("generators") ? Engine.GENERATORS : key.equals("processors") ? Engine.PROCESSORS : Engine.SESSION_ACTIONS;
            for (String n : Engine.names(l)) s.append(j++ > 0 ? "," : "").append(Wire.Json.esc(n));
            s.append(']');
        }
        s.append('}');
        Wire.send(s.toString());
    }

    /** Rebuilding the tabs: selection changes are ours, not the extension's. */
    private static boolean rebuilding;

    /** Add (or replace) a tab of the extension's window. Tabs always sit in
     *  a JTabbedPane, as Burp's suite tabs do (extensions walk up to it to
     *  select their tab; selecting one brings the window up, like Burp
     *  switching to the tab). */
    static void addTab(String title, Component c) {
        TABS.put(title, c);
        if (!HEADLESS) {
            onEdt(() -> {
                ensureFrame();
                rebuilding = true;
                try {
                    pane.removeAll();
                    for (Map.Entry<String, Component> e : TABS.entrySet()) pane.addTab(e.getKey(), e.getValue());
                    pane.setSelectedIndex(new ArrayList<>(TABS.keySet()).indexOf(title));
                } finally {
                    rebuilding = false;
                }
                frame.revalidate();
                frame.repaint();
            });
        }
    }

    /** The extension's window (Burp's suite frame), made on first use. */
    static void ensureFrame() {
        onEdt(() -> {
            if (frame != null) return;
            frame = new JFrame(title());
            frame.setDefaultCloseOperation(WindowConstants.HIDE_ON_CLOSE);
            frame.setSize(1100, 760);
            pane = new JTabbedPane() {
                // An extension selecting its tab (even the one already
                // selected) brings the window up.
                @Override public void setSelectedIndex(int index) {
                    super.setSelectedIndex(index);
                    if (!rebuilding && !frame.isShowing()) SwingUtilities.invokeLater(Ui::show);
                }
            };
            frame.getContentPane().add(pane);
            refreshBar();
        });
    }

    static void show() {
        if (HEADLESS || frame == null) return;
        onEdt(() -> {
            frame.setTitle(title());
            frame.setVisible(true);
            frame.setState(java.awt.Frame.NORMAL);
            frame.toFront();
        });
        pushState();
    }

    static void dispose() {
        if (frame != null) onEdt(() -> frame.dispose());
    }

    // ------------------------------------------------------------ the API object

    static UserInterface userInterface() {
        return Api.obj()
                .on("registerSuiteTab", a -> {
                    String title = String.valueOf(a[0]);
                    addTab(title, (Component) a[1]);
                    if (!startup) show();
                    pushState();
                    return Api.registration(() -> { TABS.remove(title); pushState(); });
                })
                .on("registerContextMenuItemsProvider", a -> {
                    MENUS.add((ContextMenuItemsProvider) a[0]);
                    pushState();
                    return Api.registration(() -> { MENUS.remove(a[0]); pushState(); });
                })
                .on("registerHttpRequestEditorProvider", a -> {
                    REQUEST_EDITORS.add((HttpRequestEditorProvider) a[0]);
                    pushState();
                    return Api.registration(() -> { REQUEST_EDITORS.remove(a[0]); pushState(); });
                })
                .on("registerHttpResponseEditorProvider", a -> {
                    RESPONSE_EDITORS.add((HttpResponseEditorProvider) a[0]);
                    pushState();
                    return Api.registration(() -> { RESPONSE_EDITORS.remove(a[0]); pushState(); });
                })
                // WebProbe has no WebSocket message editor slot: the provider
                // is kept but never asked for an editor.
                .on("registerWebSocketMessageEditorProvider", a -> {
                    WS_EDITORS.add(a[0]);
                    Logs.output("[bridge] WebSocket message editor tabs are not shown by WebProbe; the provider is registered but not used");
                    return Api.registration(() -> WS_EDITORS.remove(a[0]));
                })
                .on("createRawEditor", a -> TextEditor.create(burp.api.montoya.ui.editor.RawEditor.class, a))
                .on("createHttpRequestEditor", a -> TextEditor.create(burp.api.montoya.ui.editor.HttpRequestEditor.class, a))
                .on("createHttpResponseEditor", a -> TextEditor.create(burp.api.montoya.ui.editor.HttpResponseEditor.class, a))
                .on("createWebSocketMessageEditor", a -> TextEditor.create(burp.api.montoya.ui.editor.WebSocketMessageEditor.class, a))
                .on("applyThemeToComponent", a -> null)
                .on("currentTheme", a -> Theme.LIGHT)
                .on("currentEditorFont", a -> new Font(Font.MONOSPACED, Font.PLAIN, 13))
                .on("currentDisplayFont", a -> new Font(Font.SANS_SERIF, Font.PLAIN, 13))
                .on("swingUtils", a -> swingUtils())
                .on("menuBar", a -> menuBar())
                // Burp's Settings dialog: the panel is a tab of the extension's window.
                .on("registerSettingsPanel", a -> {
                    String title = "Settings";
                    addTab(title, ((burp.api.montoya.ui.settings.SettingsPanel) a[0]).uiComponent());
                    pushState();
                    return Api.registration(() -> { TABS.remove(title); pushState(); });
                })
                .on("openSettingsWindow", a -> { show(); return null; })
                .as(UserInterface.class);
    }

    // ------------------------------------------------------------ menu bar

    /** Menus the extension added to "Burp's" menu bar: shown on its window. */
    static final List<javax.swing.JMenu> BAR_MENUS = new CopyOnWriteArrayList<>();

    static burp.api.montoya.ui.menu.MenuBar menuBar() {
        return Api.obj().on("registerMenu", a -> {
            javax.swing.JMenu m = a[0] instanceof javax.swing.JMenu j ? j : swingMenu((burp.api.montoya.ui.menu.Menu) a[0]);
            BAR_MENUS.add(m);
            refreshBar();
            return Api.registration(() -> { BAR_MENUS.remove(m); refreshBar(); });
        }).as(burp.api.montoya.ui.menu.MenuBar.class);
    }

    static javax.swing.JMenu swingMenu(burp.api.montoya.ui.menu.Menu menu) {
        javax.swing.JMenu m = new javax.swing.JMenu(menu.caption());
        for (burp.api.montoya.ui.menu.MenuItem it : menu.menuItems()) {
            javax.swing.JMenuItem j = new javax.swing.JMenuItem(it.caption());
            if (it instanceof burp.api.montoya.ui.menu.BasicMenuItem b) j.addActionListener(e -> b.action());
            m.add(j);
        }
        return m;
    }

    static void refreshBar() {
        if (HEADLESS || frame == null) return;
        onEdt(() -> {
            javax.swing.JMenuBar bar = new javax.swing.JMenuBar();
            for (javax.swing.JMenu m : BAR_MENUS) bar.add(m);
            frame.setJMenuBar(BAR_MENUS.isEmpty() ? null : bar);
            frame.revalidate();
        });
    }

    /** Menu.menu(caption) and BasicMenuItem.basicMenuItem(caption). */
    static burp.api.montoya.ui.menu.Menu menu(String caption, List<burp.api.montoya.ui.menu.MenuItem> items) {
        Api.Obj o = Api.obj();
        o.on("caption", a -> caption).on("menuItems", a -> items)
         .on("withCaption", a -> menu(String.valueOf(a[0]), items))
         .on("withMenuItems", a -> {
             List<burp.api.montoya.ui.menu.MenuItem> l = new ArrayList<>();
             for (Object x : Messages.many(a)) l.add((burp.api.montoya.ui.menu.MenuItem) x);
             return menu(caption, l);
         });
        return o.as(burp.api.montoya.ui.menu.Menu.class);
    }

    static burp.api.montoya.ui.menu.BasicMenuItem basicMenuItem(String caption, Runnable action) {
        return Api.obj().on("caption", a -> caption)
                .on("action", a -> { if (action != null) action.run(); return null; })
                .on("withAction", a -> basicMenuItem(caption, (Runnable) a[0]))
                .on("withCaption", a -> basicMenuItem(String.valueOf(a[0]), action))
                .as(burp.api.montoya.ui.menu.BasicMenuItem.class);
    }

    static burp.api.montoya.ui.swing.SwingUtils swingUtils() {
        return Api.obj()
                .on("suiteFrame", a -> {
                    if (HEADLESS) throw new java.awt.HeadlessException("no display: WebProbe runs this extension headless");
                    ensureFrame();
                    return frame;
                })
                .on("windowForComponent", a -> SwingUtilities.getWindowAncestor((Component) a[0]))
                .on("colorForHighLight", a -> colour((HighlightColor) a[0]))
                .as(burp.api.montoya.ui.swing.SwingUtils.class);
    }

    /** Burp's light-theme row colours (WebProbe's table uses the same). */
    static Color colour(HighlightColor c) {
        switch (c) {
            case RED: return new Color(0xff, 0x64, 0x64);
            case ORANGE: return new Color(0xff, 0xc8, 0x64);
            case YELLOW: return new Color(0xff, 0xff, 0x64);
            case GREEN: return new Color(0x64, 0xff, 0x64);
            case CYAN: return new Color(0x64, 0xff, 0xff);
            case BLUE: return new Color(0x64, 0x64, 0xff);
            case PINK: return new Color(0xff, 0xc8, 0xc8);
            case MAGENTA: return new Color(0xff, 0x64, 0xff);
            case GRAY: return new Color(0xb4, 0xb4, 0xb4);
            default: return null;
        }
    }

    // ------------------------------------------------------------ context menus

    /** Items of the last menu, by id, for menu-invoke. */
    static final Map<String, AbstractButton> ITEMS = new LinkedHashMap<>();
    /** The editor message of the last menu (setRequest / setResponse land here). */
    static byte[][] edited = new byte[2][];

    /** WebProbe asks for menu items: the providers' items, flattened to
     *  "Submenu > Item" labels. */
    static String menu(int id, Map<String, Object> m) {
        ITEMS.clear();
        edited = new byte[2][];
        ContextMenuEvent ev = event(m);
        List<String[]> out = new ArrayList<>();
        for (ContextMenuItemsProvider p : MENUS) {
            List<Component> items;
            try {
                List<List<Component>> got = new ArrayList<>();
                onEdt(() -> got.add(p.provideMenuItems(ev)));
                items = got.get(0);
            } catch (Throwable t) {
                Logs.error("[bridge] context menu provider failed: " + Logs.trace(t));
                continue;
            }
            if (items != null) for (Component c : items) flatten(c, "", out);
        }
        StringBuilder s = new StringBuilder("{\"id\":" + id + ",\"items\":[");
        for (int i = 0; i < out.size(); i++) {
            s.append(i > 0 ? "," : "").append("{\"id\":").append(Wire.Json.esc(out.get(i)[0])).append(",\"label\":").append(Wire.Json.esc(out.get(i)[1])).append('}');
        }
        return s.append("]}").toString();
    }

    private static void flatten(Component c, String prefix, List<String[]> out) {
        if (c instanceof JMenu menu) {
            String p = prefix + menu.getText() + " > ";
            for (Component k : menu.getMenuComponents()) flatten(k, p, out);
        } else if (c instanceof AbstractButton b) {
            String id = String.valueOf(ITEMS.size() + 1);
            ITEMS.put(id, b);
            out.add(new String[] { id, prefix + b.getText() });
        }
    }

    /** Run one item's action; reply with any message the action set. */
    static String invoke(int id, String item) {
        edited = new byte[2][];
        AbstractButton b = ITEMS.get(item);
        boolean ok = b != null;
        if (ok) {
            try {
                onEdt(() -> {
                    ActionEvent e = new ActionEvent(b, ActionEvent.ACTION_PERFORMED, b.getActionCommand());
                    for (ActionListener l : b.getActionListeners()) l.actionPerformed(e);
                });
            } catch (Throwable t) {
                Logs.error("[bridge] context menu action failed: " + Logs.trace(t));
                ok = false;
            }
        }
        StringBuilder s = new StringBuilder("{\"id\":" + id + ",\"ok\":" + ok);
        if (edited[0] != null) s.append(",\"request\":").append(Wire.Json.esc(Wire.b64(edited[0])));
        if (edited[1] != null) s.append(",\"response\":").append(Wire.Json.esc(Wire.b64(edited[1])));
        return s.append('}').toString();
    }

    @SuppressWarnings("unchecked")
    static HttpRequestResponse pair(Map<String, Object> m) {
        Messages.Svc svc = new Messages.Svc(Wire.str(m, "host", ""), (int) Wire.num(m.get("port")), Boolean.TRUE.equals(m.get("secure")));
        HttpRequest req = (HttpRequest) Messages.request(Wire.unb64(Wire.str(m, "request", "")), svc, null, HttpRequest.class);
        Object r = m.get("response");
        HttpResponse resp = r instanceof String s && !s.isEmpty() ? (HttpResponse) Messages.response(Wire.unb64(s), null, HttpResponse.class) : null;
        return Messages.requestResponse(req, resp, Messages.annotations("", HighlightColor.NONE));
    }

    @SuppressWarnings("unchecked")
    static ContextMenuEvent event(Map<String, Object> m) {
        List<HttpRequestResponse> selected = new ArrayList<>();
        Object msgs = m.get("messages");
        if (msgs instanceof List<?> l) for (Object o : l) selected.add(pair((Map<String, Object>) o));
        InvocationType type;
        try { type = InvocationType.valueOf(Wire.str(m, "invocation", "PROXY_HISTORY")); } catch (Exception e) { type = InvocationType.PROXY_HISTORY; }
        InvocationType invocation = type;
        ToolSource tool = Messages.tool(Wire.str(m, "tool", "Proxy"));
        Optional<MessageEditorHttpRequestResponse> editor = Optional.empty();
        if (m.get("editor") instanceof Map<?, ?> em && !selected.isEmpty()) {
            editor = Optional.of(editorMessage((Map<String, Object>) em, selected.get(0)));
        }
        Optional<MessageEditorHttpRequestResponse> ed = editor;
        return Api.obj()
                .on("messageEditorRequestResponse", a -> ed)
                .on("selectedRequestResponses", a -> ed.isPresent() ? List.of() : selected)
                .on("selectedIssues", a -> List.of())
                .on("invocationType", a -> invocation)
                .on("isFrom", a -> { for (Object x : Messages.many(a)) if (x == invocation) return true; return false; })
                .on("toolType", a -> tool.toolType())
                .on("isFromTool", a -> tool.isFromTool((burp.api.montoya.core.ToolType[]) Messages.many(a).toArray(new burp.api.montoya.core.ToolType[0])))
                .on("inputEvent", a -> { throw Api.unsupported("ContextMenuEvent", "inputEvent"); })
                .as(ContextMenuEvent.class);
    }

    static MessageEditorHttpRequestResponse editorMessage(Map<String, Object> em, HttpRequestResponse rr) {
        String context = Wire.str(em, "context", "REQUEST");
        int start = (int) Wire.num(em.get("start")), end = (int) Wire.num(em.get("end")), caret = (int) Wire.num(em.get("caret"));
        Optional<Range> sel = end > start ? Optional.of(range(start, end)) : Optional.empty();
        return Api.obj()
                .on("selectionContext", a -> MessageEditorHttpRequestResponse.SelectionContext.valueOf(context))
                .on("selectionOffsets", a -> sel)
                .on("caretPosition", a -> caret)
                .on("requestResponse", a -> rr)
                .on("setRequest", a -> { edited[0] = Messages.rawOf(a[0]); return null; })
                .on("setResponse", a -> { edited[1] = Messages.rawOf(a[0]); return null; })
                .as(MessageEditorHttpRequestResponse.class);
    }

    static Range range(int start, int end) {
        return Api.obj()
                .on("startIndexInclusive", a -> start)
                .on("endIndexExclusive", a -> end)
                .on("contains", a -> { int i = ((Number) a[0]).intValue(); return i >= start && i < end; })
                .text(start + ".." + end)
                .as(Range.class);
    }

    // ------------------------------------------------------------ extension-provided editors

    /** One editor per provider, made on first use and kept. */
    static final Map<Object, ExtensionProvidedEditor> MADE = new LinkedHashMap<>();

    /** WebProbe sends its selected message to the extension's editors: each
     *  enabled one gets it and is shown as a tab of the window. */
    static String editors(int id, Map<String, Object> m) {
        HttpRequestResponse rr = pair(m);
        EditorCreationContext ctx = Api.obj()
                .on("toolSource", a -> Messages.tool(Wire.str(m, "tool", "Repeater")))
                .on("editorMode", a -> EditorMode.DEFAULT)
                .as(EditorCreationContext.class);
        List<Object> providers = new ArrayList<>(REQUEST_EDITORS);
        if (rr.response() != null) providers.addAll(RESPONSE_EDITORS);
        StringBuilder s = new StringBuilder("{\"id\":" + id + ",\"editors\":[");
        int k = 0;
        for (Object p : providers) {
            try {
                ExtensionProvidedEditor[] ed = new ExtensionProvidedEditor[1];
                onEdt(() -> {
                    ed[0] = MADE.computeIfAbsent(p, x -> x instanceof HttpRequestEditorProvider q ? q.provideHttpRequestEditor(ctx)
                            : ((HttpResponseEditorProvider) x).provideHttpResponseEditor(ctx));
                });
                boolean[] enabled = { false };
                String[] caption = { "" };
                onEdt(() -> {
                    enabled[0] = ed[0].isEnabledFor(rr);
                    caption[0] = ed[0].caption();
                    if (enabled[0]) {
                        ed[0].setRequestResponse(rr);
                        // "Editor: " keeps an editor apart from a suite tab of the same name.
                        addTab("Editor: " + caption[0], ed[0].uiComponent());
                    }
                });
                s.append(k++ > 0 ? "," : "").append("{\"caption\":").append(Wire.Json.esc(caption[0])).append(",\"enabled\":").append(enabled[0])
                 .append(",\"request\":").append(p instanceof HttpRequestEditorProvider).append('}');
            } catch (Throwable t) {
                Logs.error("[bridge] editor provider failed: " + Logs.trace(t));
            }
        }
        show();
        pushState();
        return s.append("]}").toString();
    }

    /** The first modified request from an extension editor, for Repeater. */
    static String edited(int id) {
        byte[][] got = new byte[1][];
        onEdt(() -> {
            for (ExtensionProvidedEditor e : MADE.values()) {
                if (e instanceof ExtensionProvidedHttpRequestEditor r && r.isModified()) {
                    HttpRequest q = r.getRequest();
                    if (q != null) { got[0] = Messages.rawOf(q); break; }
                }
            }
        });
        return "{\"id\":" + id + (got[0] == null ? "" : ",\"request\":" + Wire.Json.esc(Wire.b64(got[0]))) + "}";
    }

    // ------------------------------------------------------------ editors WebProbe creates for extensions

    /** Plain text-area editors (createRawEditor / createHttpRequestEditor
     *  / ...): what extensions embed in their own panels. */
    static final class TextEditor {
        static Object create(Class<?> iface, Object[] a) {
            boolean readOnly = false;
            for (Object o : Messages.many(a)) if (o == EditorOptions.READ_ONLY) readOnly = true;
            JTextArea area = new JTextArea();
            area.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 13));
            area.setEditable(!readOnly);
            JComponent ui = new JScrollPane(area);
            String[] original = { "" };
            Messages.Svc[] svc = { new Messages.Svc("", 80, false) };
            Api.Obj o = Api.obj()
                    .on("uiComponent", x -> ui)
                    .on("isModified", x -> !area.getText().equals(original[0]))
                    .on("caretPosition", x -> area.getCaretPosition())
                    .on("setCaretPosition", x -> { area.setCaretPosition(((Number) x[0]).intValue()); return null; })
                    .on("setSearchExpression", x -> null)
                    .on("setEditable", x -> { area.setEditable((Boolean) x[0]); return null; })
                    .on("selection", x -> {
                        int s = area.getSelectionStart(), e = area.getSelectionEnd();
                        if (e <= s) return Optional.empty();
                        byte[] b = area.getSelectedText().getBytes(Messages.L1);
                        return Optional.of(selection(Messages.bytes(b), s, e));
                    })
                    .on("getContents", x -> Messages.bytes(area.getText().getBytes(Messages.L1)))
                    .on("setContents", x -> { set(area, original, new String(((burp.api.montoya.core.ByteArray) x[0]).getBytes(), Messages.L1)); return null; })
                    .on("getRequest", x -> Messages.request(area.getText().getBytes(Messages.L1), svc[0], null, HttpRequest.class))
                    .on("setRequest", x -> {
                        HttpRequest q = (HttpRequest) x[0];
                        if (q != null && q.httpService() != null) svc[0] = Messages.svcOf(q.httpService());
                        set(area, original, q == null ? "" : new String(Messages.rawOf(q), Messages.L1));
                        return null;
                    })
                    .on("getResponse", x -> Messages.response(area.getText().getBytes(Messages.L1), null, HttpResponse.class))
                    .on("setResponse", x -> { set(area, original, x[0] == null ? "" : new String(Messages.rawOf(x[0]), Messages.L1)); return null; });
            return o.as(iface);
        }

        private static void set(JTextArea area, String[] original, String text) {
            onEdt(() -> { area.setText(text); area.setCaretPosition(0); });
            original[0] = text;
        }
    }

    static Selection selection(burp.api.montoya.core.ByteArray contents, int start, int end) {
        Range r = range(start, end);
        return Api.obj().on("contents", a -> contents).on("offsets", a -> r).as(Selection.class);
    }
}
