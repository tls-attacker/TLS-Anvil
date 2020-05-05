package de.rub.nds.tlstest.framework.config.delegates;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParameterException;
import com.beust.jcommander.Parameters;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.ServerDelegate;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.File;

@FunctionalInterface
interface ScriptFunction {
    void run();
}

@Parameters(commandDescription = "Test a client implementation, thus start TLS-Attacker in server mode")
public class TestClientDelegate extends ServerDelegate {
    private static final Logger LOGGER = LogManager.getLogger();

    @Parameter(names = "-script", description = "The script is executed after the receiving port for the TLS Messages is opened. " +
            "This is inteded to trigger the client under test to initiate a TLS-Connection.")
    protected String script = null;

    private ScriptFunction wakeupScript;

    @Override
    public void applyDelegate(Config config) {
        super.applyDelegate(config);

        if (this.script != null) {
            File script = new File(this.script);
            if (!script.exists()) {
                throw new ParameterException("Wakeup script does not exist!");
            }

            wakeupScript = () -> {
                ProcessBuilder processBuilder = new ProcessBuilder(this.script);
                try {
                    processBuilder.start();
                }
                catch (Exception e) {
                    LOGGER.error("Script crashed", e);
                }
            };

        }
    }


    public void executeWakeupScript() {
        this.wakeupScript.run();
    }

    public void setWakeupScript(ScriptFunction wakeupScript) {
        this.wakeupScript = wakeupScript;
    }

}
