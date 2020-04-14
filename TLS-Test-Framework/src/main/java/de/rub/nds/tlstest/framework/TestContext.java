package de.rub.nds.tlstest.framework;

import de.rub.nds.tlstest.framework.config.TestConfig;

public class TestContext {

    private TestConfig config;

    private static TestContext instance = null;
    private TestRunner testRunner = null;

    public static TestContext getInstance() {
        if (TestContext.instance == null) {
            TestContext.instance = new TestContext();
            TestContext.instance.config.parse(null);
        }
        return TestContext.instance;
    }

    public TestContext() {
        super();
        this.config = new TestConfig();
        this.testRunner = new TestRunner(this.config);
    }

    public TestContext(TestConfig config) {
        super();
        this.config = config;
    }







    public TestConfig getConfig() {
        return config;
    }

    public void setConfig(TestConfig config) {
        this.config = config;
    }

    public TestRunner getTestRunner() {
        return testRunner;
    }

    public void setTestRunner(TestRunner testRunner) {
        this.testRunner = testRunner;
    }
}
