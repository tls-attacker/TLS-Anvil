package de.rub.nds.tlstest.framework;

import de.rub.nds.tlstest.framework.config.TestConfig;
import de.rub.nds.tlstest.framework.execution.AnnotatedStateContainer;
import de.rub.nds.tlstest.framework.execution.TestRunner;
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
        this.testRunner = new TestRunner(this.config);
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
}
