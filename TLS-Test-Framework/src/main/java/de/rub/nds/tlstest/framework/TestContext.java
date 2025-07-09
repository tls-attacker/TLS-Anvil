/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework;

import de.rub.nds.anvilcore.context.AnvilTestConfig;
import de.rub.nds.anvilcore.execution.AnvilListener;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlstest.framework.config.TlsAnvilConfig;
import de.rub.nds.tlstest.framework.execution.TestPreparator;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.platform.launcher.TestPlan;

/**
 * Shared global Singleton object that stores information that are used by the JUnit extensions and
 * the test cases.
 */
public class TestContext implements AnvilListener {
    private static final Logger LOGGER = LogManager.getLogger();
    private TlsAnvilConfig config;

    private static TestContext instance = null;
    private ParallelExecutor stateExecutor;

    private FeatureExtractionResult featureExtractionResult = null;
    private ClientHelloMessage receivedClientHelloMessage;

    private int serverHandshakesSinceRestart = 0;
    private boolean aborted = false;

    public static synchronized TestContext getInstance() {
        if (TestContext.instance == null) {
            TestContext.instance = new TestContext();
        }
        return TestContext.instance;
    }

    private TestContext() {
        super();
        this.config = new TlsAnvilConfig();
    }

    public synchronized TlsAnvilConfig getConfig() {
        return config;
    }

    public synchronized void setConfig(TlsAnvilConfig config) {
        this.config = config;
    }

    public ClientHelloMessage getReceivedClientHelloMessage() {
        return receivedClientHelloMessage;
    }

    public void setReceivedClientHelloMessage(ClientHelloMessage receivedClientHelloMessage) {
        this.receivedClientHelloMessage = receivedClientHelloMessage;
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

    @Override
    public void gotConfig(AnvilTestConfig anvilConfig, String tlsConfig) {
        getConfig().fromWorker(anvilConfig, tlsConfig);
    }

    @Override
    public boolean beforeStart(TestPlan testPlan, long totalTests) {
        // print out test counts before each run
        TestPreparator.printTestInfo(testPlan);
        // run TestPreparator before each run
        return new TestPreparator(getConfig(), this).prepareTestExecution();
    }

    @Override
    public void onAborted() {
        aborted = true;
    }

    public boolean isAborted() {
        return aborted;
    }
}
