// R-03 stage 2 test extension: http(). Its HTTP handler annotates and edits
// every request (header, body, a sendRequest round trip when asked) and
// rewrites the response's Server header. Compiled by the ext_host tests.

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.requests.HttpRequest;

public class Stage2Extension implements BurpExtension, HttpHandler {
    private MontoyaApi api;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("Stage Two");
        api.http().registerHttpHandler(this);
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent req) {
        HttpRequest out = req.withAddedHeader("X-Stage2", req.toolSource().toolType().toolName() + " " + req.method() + " " + req.pathWithoutQuery());
        String port = req.headerValue("X-Target-Port");
        if (port != null) {
            HttpService target = HttpService.httpService("127.0.0.1", Integer.parseInt(port), false);
            HttpRequestResponse rr = api.http().sendRequest(HttpRequest.httpRequest(target, "GET /from-ext HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"));
            String sent = rr.hasResponse() ? rr.response().statusCode() + " " + rr.response().bodyToString() : "none";
            out = out.withRemovedHeader("X-Target-Port").withAddedHeader("X-Sent", sent);
        }
        if (req.hasParameter("body", HttpParameterType.URL)) {
            out = out.withBody("edited=" + req.parameterValue("body", HttpParameterType.URL));
        }
        req.annotations().setNotes("seen by stage2");
        return RequestToBeSentAction.continueWith(out, req.annotations().withHighlightColor(HighlightColor.CYAN));
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived resp) {
        return ResponseReceivedAction.continueWith(
                resp.withUpdatedHeader("Server", "stage2 saw " + resp.initiatingRequest().path()),
                resp.annotations().withNotes(resp.annotations().notes() + "; response " + resp.statusCode()));
    }
}
