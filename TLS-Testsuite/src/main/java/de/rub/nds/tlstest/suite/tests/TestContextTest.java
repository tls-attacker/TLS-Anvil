package de.rub.nds.tlstest.suite.tests;

import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.annotations.ClientTest;
import de.rub.nds.tlstest.framework.annotations.ServerTest;
import de.rub.nds.tlstest.framework.constants.TestEndpointType;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class TestContextTest {

    @ServerTest
    void testServerTest(TestContext context) {
        assertEquals(context.getTestEndpointType(), TestEndpointType.SERVER);
    }

    @ClientTest
    void testClientTest(TestContext context) {
        assertEquals(context.getTestEndpointType(), TestEndpointType.CLIENT);
    }

    @Test
    void testBothTest(TestContext context) {
        assertEquals(context.getTestEndpointType(), TestEndpointType.BOTH);
    }
}


