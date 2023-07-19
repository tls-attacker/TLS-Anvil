/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework;

import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlstest.framework.config.TestConfig;
import de.rub.nds.tlstest.framework.execution.TestRunner;
import java.util.Date;
import me.tongfei.progressbar.ProgressBar;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Shared global Singleton object that stores information that are used by the JUnit extensions and
 * the test cases.
 */
public class TestContext {
    private static final Logger LOGGER = LogManager.getLogger();
    private TestConfig config;

    private static TestContext instance = null;
    private TestRunner testRunner = null;
    private ParallelExecutor stateExecutor;

    private FeatureExtractionResult featureExtractionResult = null;
    private ClientHelloMessage receivedClientHelloMessage;

    private long performedHandshakes = 0;

    private ProgressBar proggressBar = null;
    private final Date startTime = new Date();

    private int serverHandshakesSinceRestart = 0;

    public static synchronized TestContext getInstance() {
        if (TestContext.instance == null) {
            TestContext.instance = new TestContext();
        }
        return TestContext.instance;
    }

    private TestContext() {
        super();
        this.config = new TestConfig();
        this.testRunner = new TestRunner(this.config, this);
    }

    public synchronized TestConfig getConfig() {
        return config;
    }

    public synchronized void setConfig(TestConfig config) {
        this.config = config;
    }

    public synchronized TestRunner getTestRunner() {
        return testRunner;
    }

    public synchronized void setTestRunner(TestRunner testRunner) {
        this.testRunner = testRunner;
    }

    public ClientHelloMessage getReceivedClientHelloMessage() {
        return receivedClientHelloMessage;
    }

    public void setReceivedClientHelloMessage(ClientHelloMessage receivedClientHelloMessage) {
        this.receivedClientHelloMessage = receivedClientHelloMessage;
    }

    public boolean isDocker() {
        return System.getenv("DOCKER") != null;
    }

    public ProgressBar getProggressBar() {
        return proggressBar;
    }

    public Date getStartTime() {
        return startTime;
    }

    public FeatureExtractionResult getFeatureExtractionResult() {
        return featureExtractionResult;
    }

    public void setFeatureExtractionResult(FeatureExtractionResult featureExtractionResult) {
        this.featureExtractionResult = featureExtractionResult;
    }

    public ParallelExecutor getStateExecutor() {
        return stateExecutor;
    }

    public void setStateExecutor(ParallelExecutor stateExecutor) {
        this.stateExecutor = stateExecutor;
    }

    public synchronized int getServerHandshakesSinceRestart() {
        return serverHandshakesSinceRestart;
    }

    public synchronized void resetServerHandshakesSinceRestart() {
        this.serverHandshakesSinceRestart = 0;
    }

    public synchronized void increaseServerHandshakesSinceRestart() {
        this.serverHandshakesSinceRestart += 1;
    }

    public long getPerformedHandshakes() {
        return performedHandshakes;
    }

    public void increasePerformedHandshakes(long performedHandshakes) {
        this.performedHandshakes += performedHandshakes;
    }
}
