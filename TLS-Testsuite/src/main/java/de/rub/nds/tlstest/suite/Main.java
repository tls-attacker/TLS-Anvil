/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite;

import com.beust.jcommander.ParameterException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.rub.nds.anvilcore.execution.TestRunner;
import de.rub.nds.anvilcore.worker.WorkerClient;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.anvil.TlsParameterIdentifierProvider;
import de.rub.nds.tlstest.framework.extractor.TestCaseExtractor;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Main entrypoint for the TLS-Attacker testsuite.
 */
public class Main {
    private static final Logger LOGGER = LogManager.getLogger();
    private static boolean finished = false;

    static {
        System.setProperty("java.util.logging.manager", "org.apache.logging.log4j.jul.LogManager");
    }

    /**
     * Creates a TLS-Anvil TestContext, pareses the command line args and runs the
     * selected processes based on the command.
     * @param args supplied command line arguments
     */
    public static void main(String[] args) {

        // create the TLS-Anvil test context singleton
        TestContext testContext = TestContext.getInstance();

        // runs in background, prints the ram usage every 2 seconds, when run in debug mode
        new Thread(
                        () -> {
                            while (!finished) {
                                LOGGER.debug(
                                        "RAM: {}/{}",
                                        (Runtime.getRuntime().totalMemory()
                                                        - Runtime.getRuntime().freeMemory())
                                                / 1000000,
                                        Runtime.getRuntime().totalMemory() / 1000000);
                                try {
                                    Thread.sleep(2000);
                                } catch (Exception ignored) {
                                }
                            }
                        })
                .start();

        try {
            // parse command line args into a TlsTestConfig object
            // this also fills an AnvilConfig object
            testContext.getConfig().parse(args);

            if (testContext.getConfig().getAnvilTestConfig().getTestPackage() != null) {
                LOGGER.info("Limiting test to those of package {}", testContext.getConfig().getAnvilTestConfig().getTestPackage());
            } else {
                // set test package if not specified via command args
                testContext.getConfig().getAnvilTestConfig().setTestPackage(Main.class.getPackageName());
            }

            switch (testContext.getConfig().getParsedCommand()) {
                case CLIENT:
                case SERVER:
                    startTestRunner(testContext);
                    break;
                case EXTRACT_TESTS:
                    startTestExtractor(testContext);
                    break;
                case WORKER:
                    startWorkerClient(testContext);
                    break;
                default:
                    LOGGER.error("Command not recognized.");
            }

        } catch (ParameterException E) {
            LOGGER.error("Could not parse provided parameters", E);
            LOGGER.error(String.join(" ", args));
            System.exit(2);
        } catch (Exception e) {
            LOGGER.error("Something went wrong", e);
            System.exit(1);
        }

        finished = true;
    }

    /**
     * Start AnvilCores TestRunner with the supplied config contained in the TLS-Anvil TestContext
     * @param testContext TLS-Anvils TestContext with filled AnvilConfig
     */
    public static void startTestRunner(TestContext testContext) throws JsonProcessingException {
        LOGGER.info("Started in testing mode.");
        ObjectMapper mapper =  new ObjectMapper();
        String additionalConfig = mapper.writeValueAsString(testContext.getConfig());
        TestRunner runner = new TestRunner(
                testContext.getConfig().getAnvilTestConfig(),
                additionalConfig,
                new TlsParameterIdentifierProvider());
        // set TLS-Anvils TestContext as listener for callbacks
        // in the beforeStart callback, the test preparation is started
        runner.setListener(testContext);

        runner.runTests();
    }

    /**
     * Starts the built-in TestCaseExtractor
     * @param testContext TLS-Anvils TestContext with filled AnvilConfig
     */
    public static void startTestExtractor(TestContext testContext) {
        LOGGER.info("Started in extract mode.");
        TestCaseExtractor extractor = new TestCaseExtractor(
                testContext.getConfig().getAnvilTestConfig().getTestPackage());
        extractor.start();
    }

    /**
     * Starts the WorkerClient of AnvilCore with the supplied config in TLS-Anvils TestContext.
     * The client connects to a backend and can start tests.
     * @param testContext TLS-Anvils TestContext with filled AnvilConfig
     */
    public static void startWorkerClient(TestContext testContext) {
        LOGGER.info("Started in worker mode.");
        WorkerClient workerClient = new WorkerClient(
                testContext.getConfig().getWorkerDelegate().getController(),
                Main.class.getPackageName(),
                new TlsParameterIdentifierProvider()
        );
        // set the TLS-Anvil TestContext as listener for callbacks
        // the gotConfig callback is used to set config parameters before a test
        // the beforeStart callback is used to start the test preparation phase
        workerClient.setListener(testContext);

        try {
            workerClient.run();
        } catch (InterruptedException e) {
            LOGGER.info("Worker interrupted, exiting.");
        }
    }
}
