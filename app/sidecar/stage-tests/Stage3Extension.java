// R-03 stage 3/4 test extension: a suite tab, a context-menu provider
// (an item, and a submenu item that sets the editor's request from the
// selection), a request editor provider, extensionData() / preferences(),
// and a few utilities(). Compiled by the ext_host tests.

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Range;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.persistence.PersistedList;
import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import burp.api.montoya.ui.editor.extension.HttpRequestEditorProvider;
import burp.api.montoya.utilities.CompressionType;
import burp.api.montoya.utilities.DigestAlgorithm;

import java.awt.Component;
import java.util.List;
import javax.swing.JLabel;
import javax.swing.JMenu;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JTextArea;

public class Stage3Extension implements BurpExtension {
    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("Stage Three");
        JPanel tab = new JPanel();
        tab.add(new JLabel("stage three"));
        api.userInterface().registerSuiteTab("Stage3", tab);
        api.userInterface().registerContextMenuItemsProvider(new ContextMenuItemsProvider() {
            @Override
            public List<Component> provideMenuItems(ContextMenuEvent event) {
                JMenuItem log = new JMenuItem("Log selection");
                log.addActionListener(e -> api.logging().logToOutput("menu tool=" + event.toolType() + " type=" + event.invocationType()));
                JMenu tools = new JMenu("Tools");
                JMenuItem tag = new JMenuItem("Tag request");
                tag.addActionListener(e -> {
                    MessageEditorHttpRequestResponse ed = event.messageEditorRequestResponse().orElseThrow();
                    HttpRequest req = ed.requestResponse().request();
                    Range r = ed.selectionOffsets().orElseThrow();
                    String sel = req.toString().substring(r.startIndexInclusive(), r.endIndexExclusive());
                    ed.setRequest(req.withAddedHeader("X-Stage3", sel + " " + ed.selectionContext()));
                });
                tools.add(tag);
                return List.of(log, tools);
            }
        });
        api.userInterface().registerHttpRequestEditorProvider(new HttpRequestEditorProvider() {
            @Override
            public ExtensionProvidedHttpRequestEditor provideHttpRequestEditor(EditorCreationContext ctx) {
                JTextArea area = new JTextArea();
                HttpRequest[] current = new HttpRequest[1];
                return new ExtensionProvidedHttpRequestEditor() {
                    public HttpRequest getRequest() { return current[0].withBody(area.getText()); }
                    public void setRequestResponse(HttpRequestResponse rr) { current[0] = rr.request(); area.setText(rr.request().bodyToString()); }
                    public boolean isEnabledFor(HttpRequestResponse rr) { return rr.request().hasHeader("X-Edit"); }
                    public String caption() { return "Stage3 editor"; }
                    public Component uiComponent() { return area; }
                    public Selection selectedData() { return null; }
                    public boolean isModified() { return !area.getText().equals(current[0] == null ? "" : current[0].bodyToString()); }
                };
            }
        });
        // extensionData(): count the loads, keep a child object and a list.
        PersistedObject data = api.persistence().extensionData();
        Integer runs = data.getInteger("runs");
        api.logging().logToOutput("runs before=" + runs + " child=" + (data.getChildObject("child") == null ? null : data.getChildObject("child").getStringList("names")));
        data.setInteger("runs", runs == null ? 1 : runs + 1);
        PersistedObject child = PersistedObject.persistedObject();
        PersistedList<String> names = PersistedList.persistedStringList();
        names.add("a");
        names.add("b");
        child.setStringList("names", names);
        data.setChildObject("child", child);
        data.setHttpRequest("req", HttpRequest.httpRequest("GET /saved HTTP/1.1\r\nHost: s.test\r\n\r\n"));
        api.persistence().preferences().setString("theme", "dark");
        api.logging().logToOutput("pref=" + api.persistence().preferences().getString("theme"));
        // utilities()
        var u = api.utilities();
        api.logging().logToOutput("b64=" + u.base64Utils().encodeToString("hi"));
        api.logging().logToOutput("sha256=" + u.stringUtils().convertAsciiToHexString(new String(u.cryptoUtils().generateDigest(ByteArray.byteArray("abc"), DigestAlgorithm.SHA_256).getBytes(), java.nio.charset.StandardCharsets.ISO_8859_1)).substring(0, 8));
        ByteArray z = u.compressionUtils().compress(ByteArray.byteArray("zip me"), CompressionType.GZIP);
        api.logging().logToOutput("gzip=" + u.compressionUtils().decompress(z, CompressionType.GZIP));
        api.logging().logToOutput("url=" + u.urlUtils().encode("a b&c") + " html=" + u.htmlUtils().encode("<x>") + " hex=" + u.numberUtils().convertDecimalToHex("255"));
        api.logging().logToOutput("json=" + u.jsonUtils().read("{\"a\":{\"b\":[1,2]}}", "a.b[1]") + " " + u.jsonUtils().update("{\"a\":1}", "a", "2"));
        api.logging().logToOutput("headless window=" + safe(() -> api.userInterface().swingUtils().suiteFrame()));
    }

    private static String safe(java.util.concurrent.Callable<Object> c) {
        try { return String.valueOf(c.call() != null); } catch (Exception e) { return e.getClass().getSimpleName(); }
    }
}
