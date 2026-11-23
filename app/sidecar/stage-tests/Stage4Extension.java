// R-03 stage 4/5 test extension: an active scan check (payload placed by
// WebProbe's insertion points, request through the scan's send path), a
// passive scan check, an Intruder payload generator and processor, and a
// context-menu action that tours proxy(), scope(), siteMap(), repeater(),
// organizer(), intruder(), comparer(), decoder() and http().cookieJar().
// Compiled by the ext_host tests.

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.scanner.scancheck.ActiveScanCheck;
import burp.api.montoya.scanner.scancheck.PassiveScanCheck;
import burp.api.montoya.scanner.scancheck.ScanCheckType;

import java.awt.Component;
import java.util.List;
import javax.swing.JMenuItem;

public class Stage4Extension implements BurpExtension {
    private final burp.api.montoya.collaborator.CollaboratorClient[] client = new burp.api.montoya.collaborator.CollaboratorClient[1];

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("Stage Four");
        api.scanner().registerActiveScanCheck(new ActiveScanCheck() {
            public String checkName() { return "stage4 reflection"; }
            public AuditResult doCheck(HttpRequestResponse base, AuditInsertionPoint point, Http http) {
                if (!point.name().equals("q")) return AuditResult.auditResult(List.of());
                HttpRequest probe = point.buildHttpRequestWithPayload(ByteArray.byteArray("st4<probe>"));
                HttpRequestResponse rr = http.sendRequest(probe);
                api.logging().logToOutput("active sent " + probe.path() + " got " + (rr.hasResponse() ? rr.response().statusCode() : -1));
                if (rr.hasResponse() && rr.response().bodyToString().contains("st4<probe>")) {
                    return AuditResult.auditResult(AuditIssue.auditIssue("Stage4 reflection", "The value of <b>q</b> is reflected.", "Encode it.",
                            base.request().url(), AuditIssueSeverity.HIGH, AuditIssueConfidence.CERTAIN, null, null, AuditIssueSeverity.HIGH, rr));
                }
                return AuditResult.auditResult(List.of());
            }
            public ConsolidationAction consolidateIssues(AuditIssue a, AuditIssue b) { return ConsolidationAction.KEEP_EXISTING; }
        }, ScanCheckType.PER_INSERTION_POINT);
        api.scanner().registerPassiveScanCheck(new PassiveScanCheck() {
            public String checkName() { return "stage4 passive"; }
            public AuditResult doCheck(HttpRequestResponse rr) {
                if (rr.response() != null && rr.response().bodyToString().contains("secret")) {
                    return AuditResult.auditResult(AuditIssue.auditIssue("Stage4 passive", "A secret is shown.", null, rr.request().url(),
                            AuditIssueSeverity.INFORMATION, AuditIssueConfidence.FIRM, null, null, AuditIssueSeverity.INFORMATION, List.of(rr)));
                }
                return AuditResult.auditResult(List.of());
            }
            public ConsolidationAction consolidateIssues(AuditIssue a, AuditIssue b) { return ConsolidationAction.KEEP_BOTH; }
        }, ScanCheckType.PER_REQUEST);
        api.intruder().registerPayloadGeneratorProvider(new burp.api.montoya.intruder.PayloadGeneratorProvider() {
            public String displayName() { return "Stage4 generator"; }
            public burp.api.montoya.intruder.PayloadGenerator providePayloadGenerator(burp.api.montoya.intruder.AttackConfiguration cfg) {
                int points = cfg.requestTemplate().insertionPointOffsets().size();
                int[] n = { 0 };
                return point -> ++n[0] > 3 ? burp.api.montoya.intruder.GeneratedPayload.end()
                        : burp.api.montoya.intruder.GeneratedPayload.payload(new String(point.baseValue().getBytes()) + "-" + n[0] + "-" + points);
            }
        });
        api.intruder().registerPayloadProcessor(new burp.api.montoya.intruder.PayloadProcessor() {
            public String displayName() { return "Stage4 processor"; }
            public burp.api.montoya.intruder.PayloadProcessingResult processPayload(burp.api.montoya.intruder.PayloadData d) {
                String v = new String(d.currentPayload().getBytes());
                if (v.contains("-2-")) return burp.api.montoya.intruder.PayloadProcessingResult.skipPayload();
                return burp.api.montoya.intruder.PayloadProcessingResult.usePayload(ByteArray.byteArray(v + "-p" + new String(d.insertionPoint().baseValue().getBytes())));
            }
        });
        var bar = api.userInterface().menuBar().registerMenu(burp.api.montoya.ui.menu.Menu.menu("Stage4 menu")
                .withMenuItems(burp.api.montoya.ui.menu.BasicMenuItem.basicMenuItem("Say hi").withAction(() -> api.logging().logToOutput("hi"))));
        api.logging().logToOutput("menu registered " + bar.isRegistered() + " ai=" + api.ai().isEnabled());
        api.http().registerSessionHandlingAction(new burp.api.montoya.http.sessions.SessionHandlingAction() {
            public String name() { return "Stage4 session"; }
            public burp.api.montoya.http.sessions.ActionResult performAction(burp.api.montoya.http.sessions.SessionHandlingActionData d) {
                return burp.api.montoya.http.sessions.ActionResult.actionResult(d.request().withHeader("X-Stage4", "token-" + d.macroRequestResponses().size()));
            }
        });
        api.proxy().registerWebSocketCreationHandler(creation -> {
            api.logging().logToOutput("ws open " + creation.upgradeRequest().path());
            creation.proxyWebSocket().registerProxyMessageHandler(new burp.api.montoya.proxy.websocket.ProxyMessageHandler() {
                public burp.api.montoya.proxy.websocket.TextMessageReceivedAction handleTextMessageReceived(burp.api.montoya.proxy.websocket.InterceptedTextMessage m) {
                    if (m.payload().contains("drop")) return burp.api.montoya.proxy.websocket.TextMessageReceivedAction.drop();
                    return burp.api.montoya.proxy.websocket.TextMessageReceivedAction.continueWith(m.payload() + "+ext");
                }
                public burp.api.montoya.proxy.websocket.TextMessageToBeSentAction handleTextMessageToBeSent(burp.api.montoya.proxy.websocket.InterceptedTextMessage m) {
                    return burp.api.montoya.proxy.websocket.TextMessageToBeSentAction.continueWith(m.payload() + (m.direction() == burp.api.montoya.websocket.Direction.CLIENT_TO_SERVER ? ">" : "<"));
                }
                public burp.api.montoya.proxy.websocket.BinaryMessageReceivedAction handleBinaryMessageReceived(burp.api.montoya.proxy.websocket.InterceptedBinaryMessage m) {
                    return burp.api.montoya.proxy.websocket.BinaryMessageReceivedAction.continueWith(m.payload());
                }
                public burp.api.montoya.proxy.websocket.BinaryMessageToBeSentAction handleBinaryMessageToBeSent(burp.api.montoya.proxy.websocket.InterceptedBinaryMessage m) {
                    return burp.api.montoya.proxy.websocket.BinaryMessageToBeSentAction.continueWith(m.payload());
                }
                public void onClose() { api.logging().logToOutput("ws closed"); }
            });
        });
        api.userInterface().registerContextMenuItemsProvider(new burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider() {
          @Override
          public List<Component> provideMenuItems(burp.api.montoya.ui.contextmenu.ContextMenuEvent event) {
            JMenuItem tour = new JMenuItem("Engine tour");
            tour.addActionListener(e -> {
                var log = api.logging();
                log.logToOutput("history=" + api.proxy().history().size() + " first=" + api.proxy().history().get(0).request().path()
                        + " filtered=" + api.proxy().history(item -> item.request().path().equals("/hist")).size());
                api.proxy().enableIntercept();
                log.logToOutput("intercept=" + api.proxy().isInterceptEnabled());
                api.proxy().disableIntercept();
                api.scope().includeInScope("http://scope.test/");
                log.logToOutput("scope=" + api.scope().isInScope("http://scope.test/x") + "," + api.scope().isInScope("http://other.test/"));
                HttpRequest r = HttpRequest.httpRequestFromUrl("http://site.test/added");
                api.siteMap().add(HttpRequestResponse.httpRequestResponse(r, null));
                api.siteMap().add(AuditIssue.auditIssue("Stage4 sitemap issue", "added", null, "http://site.test/added", AuditIssueSeverity.LOW,
                        AuditIssueConfidence.TENTATIVE, null, null, AuditIssueSeverity.LOW, List.of()));
                log.logToOutput("sitemap=" + api.siteMap().requestResponses().size() + " issues=" + api.siteMap().issues().size());
                api.repeater().sendToRepeater(r, "From Stage4");
                api.http().cookieJar().setCookie("sid", "abc", "site.test", "/", null);
                log.logToOutput("cookies=" + api.http().cookieJar().cookies().get(0).name());
                client[0] = api.collaborator().createClient();
                log.logToOutput("payload=" + client[0].generatePayload() + " bare=" + client[0].generatePayload(burp.api.montoya.collaborator.PayloadOption.WITHOUT_SERVER_LOCATION)
                        + " server=" + client[0].server().address());
                api.organizer().sendToOrganizer(HttpRequestResponse.httpRequestResponse(r, null));
                log.logToOutput("organizer=" + api.organizer().items().size() + " " + api.organizer().items().get(0).request().path()
                        + " " + api.organizer().items().get(0).status());
                api.intruder().sendToIntruder(burp.api.montoya.http.HttpService.httpService("site.test", 8443, true),
                        burp.api.montoya.intruder.HttpRequestTemplate.httpRequestTemplate(ByteArray.byteArray("GET /?a=1 HTTP/1.1\r\n\r\n"),
                                List.of(burp.api.montoya.core.Range.range(8, 9))));
                api.comparer().sendToComparer(ByteArray.byteArray("left"), ByteArray.byteArray("right"));
                api.decoder().sendToDecoder(ByteArray.byteArray("to decode"));
            });
            JMenuItem collab = new JMenuItem("Collaborator check");
            collab.addActionListener(e -> {
                var all = client[0].getAllInteractions();
                api.logging().logToOutput("interactions=" + all.size() + (all.isEmpty() ? "" : " type=" + all.get(0).type() + " client=" + all.get(0).clientIp().getHostAddress()
                        + " id=" + all.get(0).id()));
            });
            return List.<Component>of(tour, collab);
          }
        });
    }
}
