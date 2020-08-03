package de.rub.nds.tlstest.framework.testClasses;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.junitExtensions.EndpointCondition;
import de.rub.nds.tlstest.framework.junitExtensions.KexCondition;
import de.rub.nds.tlstest.framework.junitExtensions.MethodConditionExtension;
import de.rub.nds.tlstest.framework.junitExtensions.TestWatcher;
import de.rub.nds.tlstest.framework.junitExtensions.TlsVersionCondition;
import de.rub.nds.tlstest.framework.junitExtensions.WorkflowRunnerResolver;
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

