package de.rub.nds.tlstest.suite;


import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlstest.framework.TestRunner;
import de.rub.nds.tlstest.framework.config.TestConfig;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class Main {
    private static final Logger LOGGER = LogManager.getLogger();

    public static void main(String[] args) {
        TestConfig testConfig = new TestConfig();

        JCommander commander = new JCommander(testConfig);

        try {
//            commander.parse(args);
//            if (testConfig.getGeneralDelegate().isHelp()) {
//                commander.usage();
//                return;
//            }

            Config config = testConfig.createConfig(Config.createConfig());

            TestRunner runner = new TestRunner(config);
            runner.runTests(Main.class);
        }
        catch (ParameterException E) {
            LOGGER.error("Could not parse provided parameters", E);
            commander.usage();
        }
    }
}