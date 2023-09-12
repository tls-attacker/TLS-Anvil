package de.rub.nds.tlstest.framework.config.delegates;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.Parameters;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.Delegate;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;

@Parameters(
        commandDescription =
                "Starts TLS-Anvil in worker mode, accepting commands from the Anvil web ui.")
public class WorkerDelegate extends Delegate {

    @Parameter(
            names = "-controller",
            description = "Hostname or ip address of the Anvil web backend server.",
            required = true)
    private String controller = "backend:5001";

    @Parameter(names = "-name", description = "Name of the worker, as seen in the web ui.")
    private String workerName = "worker " + (int) (Math.random() * 1000);

    public String getController() {
        return controller;
    }

    public String getWorkerName() {
        return workerName;
    }

    @Override
    public void applyDelegate(Config config) throws ConfigurationException {}
}
