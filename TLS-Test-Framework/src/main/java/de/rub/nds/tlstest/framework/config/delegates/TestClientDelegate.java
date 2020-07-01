package de.rub.nds.tlstest.framework.config.delegates;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.Parameters;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.ServerDelegate;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.net.ServerSocket;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;


@Parameters(commandDescription = "Test a client implementation, thus start TLS-Attacker in server mode")
public class TestClientDelegate extends ServerDelegate {
    private static final Logger LOGGER = LogManager.getLogger();

    @Parameter(names = "-wakeupScript", description = "The script is executed before each TLS Handshake to trigger the client under test. " +
            "This command takes a variable number of arguments.", variableArity = true)
    protected List<String> wakeupScriptCommand = new ArrayList<>();

    private Callable<Integer> wakeupScript;
    private ServerSocket serverSocket;

    @Override
    public void applyDelegate(Config config) {
        super.applyDelegate(config);

        if (this.wakeupScriptCommand.size() > 0) {
            wakeupScript = () -> {
                ProcessBuilder processBuilder = new ProcessBuilder(wakeupScriptCommand);
                Process p = processBuilder.start();
                p.waitFor();
                return p.exitValue();
            };
        }

        try {
            serverSocket = new ServerSocket(this.port);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

    }


    public int executeWakeupScript() throws Exception {
        return this.wakeupScript.call();
    }

    public Callable<Integer> getWakeupScript() {
        return wakeupScript;
    }

    public void setWakeupScript(Callable<Integer> wakeupScript) {
        this.wakeupScript = wakeupScript;
    }

    public ServerSocket getServerSocket() {
        return serverSocket;
    }

    public void setServerSocket(ServerSocket serverSocket) {
        this.serverSocket = serverSocket;
    }
}
