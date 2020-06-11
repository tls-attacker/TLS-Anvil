package de.rub.nds.tlstest.framework.testClasses;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.junitExtensions.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith({
        TestWatcher.class,
        EndpointCondition.class,
        TlsVersionCondition.class,
        KexCondition.class,
        MethodConditionExtension.class,
        WorkflowRunnerResolver.class
})
public abstract class TlsBaseTest {
    protected static final Logger LOGGER = LogManager.getLogger();

    protected TestContext context;

    public TlsBaseTest() {
        this.context = TestContext.getInstance();
    }

    public void setTestContext(TestContext testCotext) {
        this.context = testCotext;
    }

    public TestContext getTestContext() {
        return context;
    }

    public abstract Config getConfig();
}

