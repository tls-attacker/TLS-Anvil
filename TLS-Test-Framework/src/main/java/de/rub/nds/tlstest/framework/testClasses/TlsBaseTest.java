package de.rub.nds.tlstest.framework.testClasses;

import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.junitExtensions.EndpointCondition;
import de.rub.nds.tlstest.framework.junitExtensions.KexCondition;
import de.rub.nds.tlstest.framework.junitExtensions.TlsVersionCondition;
import de.rub.nds.tlstest.framework.junitExtensions.WorkflowRunnerResolver;
import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith({ EndpointCondition.class, TlsVersionCondition.class, KexCondition.class, WorkflowRunnerResolver.class })
public class TlsBaseTest {

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
}

