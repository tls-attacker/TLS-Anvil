package de.rub.nds.tlstest.suite;


import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlstest.framework.TestRunner;
import de.rub.nds.tlstest.framework.config.TestConfig;
import de.rub.nds.tlstest.framework.config.delegates.TestClientDelegate;
import de.rub.nds.tlstest.framework.config.delegates.TestServerDelegate;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class Main {
    private static final Logger LOGGER = LogManager.getLogger();

    public static void main(String[] args) {
        TestClientDelegate testClientDelegate = new TestClientDelegate();
        TestServerDelegate testServerDelegate = new TestServerDelegate();

        TestConfig testConfig = new TestConfig();
        testConfig.setTestClientDelegate(testClientDelegate);
        testConfig.setTestServerDelegate(testServerDelegate);


        JCommander jc = JCommander.newBuilder()
                .addObject(testConfig)
                .addCommand("client", testClientDelegate)
                .addCommand("server", testServerDelegate)
                .build();

        try {
            jc.parse(args);
            if (jc.getParsedCommand() == null) {
                throw new ParameterException("You have to use the client or server command");
            }

            testConfig.setTestEndpointMode(jc.getParsedCommand());

            if (testConfig.getGeneralDelegate().isHelp()) {
                jc.usage();
                return;
            }

            Config config = testConfig.createConfig();

            TestRunner runner = new TestRunner(config);
            runner.runTests(Main.class);
        }
        catch (ParameterException E) {
            LOGGER.error("Could not parse provided parameters", E);
            jc.usage();
        }
    }
}
