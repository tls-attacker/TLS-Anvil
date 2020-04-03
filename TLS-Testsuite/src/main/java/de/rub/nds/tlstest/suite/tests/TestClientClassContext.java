package de.rub.nds.tlstest.suite.tests;

import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.annotations.ClientTest;
import de.rub.nds.tlstest.framework.annotations.ServerTest;
import de.rub.nds.tlstest.framework.constants.TestEndpointType;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

@ClientTest
public class TestClientClassContext {

    @Test
    void testServerTest(TestContext context) {
        assertEquals(context.getTestEndpointType(), TestEndpointType.CLIENT);
    }

    @ServerTest
    void testClientTest(TestContext context) {
        assertEquals(context.getTestEndpointType(), TestEndpointType.SERVER);
    }
}
