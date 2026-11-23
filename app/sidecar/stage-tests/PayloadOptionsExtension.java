// R-20: payload.server() must reflect WITHOUT_SERVER_LOCATION.
import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.PayloadOption;

public class PayloadOptionsExtension implements BurpExtension {
    private static void check(boolean ok, String message) {
        if (!ok) throw new AssertionError(message);
    }

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("Payload options regression");
        var client = api.collaborator().createClient();
        var located = client.generatePayload();
        check(located.toString().equals("option1.oast.test"), "default text includes server");
        check(located.id().toString().equals("option1"), "default interaction id");
        check(located.server().orElseThrow().address().equals("oast.test"), "default server metadata");
        var bare = client.generatePayload(PayloadOption.WITHOUT_SERVER_LOCATION);
        check(bare.toString().equals("option2"), "bare payload text");
        check(bare.id().toString().equals("option2"), "bare interaction id is retained");
        check(bare.server().isEmpty(), "bare payload must not report server metadata");
        var generated = api.collaborator().defaultPayloadGenerator().generatePayload(PayloadOption.WITHOUT_SERVER_LOCATION);
        check(generated.toString().equals("option3"), "default generator honors bare option");
        check(generated.server().isEmpty(), "default generator omits server metadata");
        check(located.server().isPresent(), "payload metadata is independent");
        api.logging().logToOutput("payload options regression passed");
    }
}
