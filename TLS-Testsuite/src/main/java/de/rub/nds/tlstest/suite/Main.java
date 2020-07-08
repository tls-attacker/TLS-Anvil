package de.rub.nds.tlstest.suite;


import com.beust.jcommander.ParameterException;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.utils.ExecptionPrinter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class Main {
    private static final Logger LOGGER = LogManager.getLogger();

    public static void main(String[] args) {

        TestContext testContext = new TestContext();

        try {
            testContext.getConfig().parse(args);

            testContext.getTestRunner().runTests(Main.class);
        }
        catch (ParameterException E) {
            LOGGER.error("Could not parse provided parameters", E);
            testContext.getConfig().getArgParser().usage();
        } catch (Exception e) {
            LOGGER.error(ExecptionPrinter.stacktraceToString(e));
            System.exit(3);
        }
    }
}
