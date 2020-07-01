package de.rub.nds.tlstest.framework;

import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlstest.framework.config.TestConfig;
import de.rub.nds.tlstest.framework.execution.AnnotatedStateContainer;
import de.rub.nds.tlstest.framework.execution.TestRunner;
import me.tongfei.progressbar.ProgressBar;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.HashMap;
import java.util.Map;

public class TestContext {
    private static final Logger LOGGER = LogManager.getLogger();
    private TestConfig config;

    private static TestContext instance = null;
    private TestRunner testRunner = null;

    private final Map<String, AnnotatedStateContainer> testResults = new HashMap<>();
    private boolean initializationFailed = false;
    private ClientHelloMessage receivedClientHelloMessage;

    private long totalTests = 0;
    private long testsDone = 0;
    private long testsDisabled = 0;
    private long testsFailed = 0;
    private long testsSucceeded = 0;

    private ProgressBar proggressBar = null;


    synchronized public static TestContext getInstance() {
        if (TestContext.instance == null) {
            TestContext.instance = new TestContext();
            try {
                TestContext.instance.config.parse(null);
                TestContext.instance.getTestRunner().prepareTestExecution();
            } catch(Exception e) {
                TestContext.instance.initializationFailed = true;
                throw new RuntimeException(e);
            }
        }
        if (TestContext.instance.initializationFailed) {
            throw new RuntimeException();
        }
        return TestContext.instance;
    }

    public TestContext() {
        super();
        this.config = new TestConfig();
        this.testRunner = new TestRunner(this.config, this);
        TestContext.instance = this;
    }

    public TestContext(TestConfig config) {
        super();
        this.config = config;
    }





    synchronized public TestConfig getConfig() {
        return config;
    }

    synchronized public void setConfig(TestConfig config) {
        this.config = config;
    }

    synchronized public TestRunner getTestRunner() {
        return testRunner;
    }

    synchronized public void setTestRunner(TestRunner testRunner) {
        this.testRunner = testRunner;
    }

    synchronized public Map<String, AnnotatedStateContainer> getTestResults() {
        return testResults;
    }

    synchronized public void addTestResult(AnnotatedStateContainer result) {
        testResults.put(result.getUniqueId(), result);
    }

    public ClientHelloMessage getReceivedClientHelloMessage() {
        return receivedClientHelloMessage;
    }

    public void setReceivedClientHelloMessage(ClientHelloMessage receivedClientHelloMessage) {
        this.receivedClientHelloMessage = receivedClientHelloMessage;
    }

    public long getTotalTests() {
        return totalTests;
    }

    public void setTotalTests(long totalTests) {
        proggressBar = new ProgressBar("Progress", totalTests);
        this.totalTests = totalTests;
    }

    public long getTestsDone() {
        return testsDone;
    }

    public void testFinished() {
        testsDone += 1;
        if (proggressBar != null) {
            proggressBar.stepBy(1);

            if (proggressBar.getMax() <= proggressBar.getCurrent()) {
                proggressBar.close();
            }
        }
    }

    public void testDisabled() {
        testsDisabled++;
    }

    public void testSucceeded() {
        testsSucceeded++;
    }

    public void testFailed() {
        testsFailed++;
    }



    public ProgressBar getProggressBar() {
        return proggressBar;
    }

    public long getTestsDisabled() {
        return testsDisabled;
    }

    public long getTestsFailed() {
        return testsFailed;
    }

    public long getTestsSucceeded() {
        return testsSucceeded;
    }
}
