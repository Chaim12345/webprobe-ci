import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.proxy.http.*;

/** Loopback Repeater regression. Proxy-only handlers must never run here. */
public class RepeaterHttpExtension implements BurpExtension, HttpHandler {
    private MontoyaApi api;

    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("Repeater HTTP regression");
        api.http().registerHttpHandler(this);
        api.proxy().registerRequestHandler(new ProxyRequestHandler() {
            public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest req) {
                api.logging().logToError("PROXY REQUEST HANDLER RAN");
                return ProxyRequestReceivedAction.continueWith(req.withAddedHeader("X-Proxy-Only", "1"));
            }
            public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest req) {
                return ProxyRequestToBeSentAction.continueWith(req);
            }
        });
        api.proxy().registerResponseHandler(new ProxyResponseHandler() {
            public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse resp) {
                api.logging().logToError("PROXY RESPONSE HANDLER RAN");
                return ProxyResponseReceivedAction.continueWith(resp);
            }
            public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse resp) {
                return ProxyResponseToBeSentAction.continueWith(resp);
            }
        });
    }

    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent req) {
        api.logging().logToOutput("request " + req.toolSource().toolType().toolName() + " " + req.path());
        // Re-add rather than replace so duplicate dispatch is detectable.
        return RequestToBeSentAction.continueWith(req.withAddedHeader("X-Parity-Probe", "1"));
    }

    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived resp) {
        api.logging().logToOutput("response " + resp.toolSource().toolType().toolName() + " " + resp.initiatingRequest().path());
        return ResponseReceivedAction.continueWith(resp
                .withAddedHeader("X-Handler-Tool", resp.toolSource().toolType().toolName())
                .withAddedHeader("X-Initiating-Probe", resp.initiatingRequest().headerValue("X-Parity-Probe")));
    }
}
