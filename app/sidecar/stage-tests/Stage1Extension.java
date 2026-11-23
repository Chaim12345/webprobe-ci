// R-03 stage 1 test extension: the load path. Names itself, registers an
// unloading handler, uses every logging() channel, reads burpSuite(), and
// calls two things WebProbe does not bridge (each must fail with the
// standard message, reported once). Compiled by the ext_host tests.

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.burpsuite.TaskExecutionEngine;

public class Stage1Extension implements BurpExtension {
    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("Stage One");
        api.extension().registerUnloadingHandler(() -> api.logging().logToOutput("stage1 unloaded"));
        api.logging().logToOutput("filename=" + new java.io.File(api.extension().filename()).getName() + " bapp=" + api.extension().isBapp());
        api.logging().logToError("an error line");
        api.logging().raiseInfoEvent("stage1 event");
        api.logging().output().println("via output stream");
        api.logging().logToOutput("version=" + api.burpSuite().version().name() + " edition=" + api.burpSuite().version().edition());
        TaskExecutionEngine engine = api.burpSuite().taskExecutionEngine();
        engine.setState(TaskExecutionEngine.TaskExecutionEngineState.PAUSED);
        api.logging().logToOutput("state=" + engine.getState() + " args=" + api.burpSuite().commandLineArguments().size());
        for (int i = 0; i < 2; i++) {
            try {
                api.bambda();
            } catch (UnsupportedOperationException e) {
                api.logging().logToOutput("caught: " + e.getMessage());
            }
        }
        try {
            api.burpSuite().exportProjectOptionsAsJson();
        } catch (UnsupportedOperationException e) {
            api.logging().logToOutput("caught: " + e.getMessage());
        }
    }
}
