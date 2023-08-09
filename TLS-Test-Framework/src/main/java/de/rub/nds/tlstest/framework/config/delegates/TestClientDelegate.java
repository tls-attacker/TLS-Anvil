/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.config.delegates;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.Parameters;
import com.fasterxml.jackson.annotation.JsonIgnore;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.ServerDelegate;
import de.rub.nds.tlsattacker.core.state.State;
import java.io.IOException;
import java.net.ServerSocket;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@Parameters(
        commandDescription = "Test a client implementation, thus start TLS-Attacker in server mode")
public class TestClientDelegate extends ServerDelegate {
    private static final Logger LOGGER = LogManager.getLogger();

    @Parameter(
            names = "-triggerScript",
            description =
                    "The script is executed before each TLS Handshake to trigger the client under test. "
                            + "This command takes a variable number of arguments.",
            variableArity = true)
    protected List<String> triggerScriptCommand = new ArrayList<>();

    @JsonIgnore
    private Function<State, Integer> triggerScript;
    @JsonIgnore
    private ServerSocket serverSocket;

    @Override
    public void applyDelegate(Config config) {
        super.applyDelegate(config);

        if (this.triggerScriptCommand.size() > 0) {
            triggerScript =
                    (State state) -> {
                        try {
                            ProcessBuilder processBuilder =
                                    new ProcessBuilder(triggerScriptCommand);
                            Process p = processBuilder.start();
                            return 0;
                        } catch (IOException ex) {
                            LOGGER.error(ex);
                            return 1;
                        }
                    };
        }

        try {
            serverSocket = new ServerSocket(this.port);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public int executeTriggerScript(State state) throws Exception {
        return this.triggerScript.apply(state);
    }

    public Function<State, Integer> getTriggerScript() {
        return triggerScript;
    }

    public void setTriggerScript(Function<State, Integer> triggerScript) {
        this.triggerScript = triggerScript;
    }

    public ServerSocket getServerSocket() {
        return serverSocket;
    }

    public void setServerSocket(ServerSocket serverSocket) {
        this.serverSocket = serverSocket;
    }
}
