package de.rub.nds.tlstest.framework;

import de.rub.nds.tlstest.framework.junitExtensions.EndpointCondition;
import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith({ EndpointCondition.class })
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

