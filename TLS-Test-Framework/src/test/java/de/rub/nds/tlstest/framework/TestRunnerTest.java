package de.rub.nds.tlstest.framework;

import de.rub.nds.tlstest.framework.config.TestConfig;
import org.junit.Test;

import java.net.URL;

import static org.junit.Assert.*;

public class TestRunnerTest {

    @Test
    public void test_clientPreparation() {
        TestContext context = new TestContext();

        URL scriptPath = TestRunnerTest.class.getClassLoader().getResource("trigger.sh");
        String path = scriptPath.toString().replaceAll("^file:", "");

        context.getConfig().parse(new String[]{"client", "-port", "443", "-script", path});
        context.getTestRunner().prepareTestExecution();

        assertTrue("No ciphersuites supported", context.getConfig().getSiteReport().getCipherSuites().size() > 0);

    }
}
