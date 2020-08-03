package de.rub.nds.tlstest.framework.annotations.endpoint;

import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.annotations.ClientTest;
import de.rub.nds.tlstest.framework.annotations.ServerTest;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.junitExtensions.EndpointCondition;
import de.rub.nds.tlstest.framework.utils.ConditionTest;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.extension.RegisterExtension;

@ClientTest
public class ClientAnnotationClassServerTest {

    @RegisterExtension
    static ConditionTest ext = new ConditionTest(EndpointCondition.class);

    @BeforeAll
    static void setup() {
        TestContext testContext = new TestContext();
        testContext.getConfig().parse(new String[]{ "server", "-connect", "alphanudel.de" });
    }

    @ClientTest
    public void not_execute_unsupportedForConfig() { }

    @TlsTest
    public void not_execute_inheritedFromClassAnnotation() { }

    @ServerTest
    public void execute_supportedModeForConfig() { }

}