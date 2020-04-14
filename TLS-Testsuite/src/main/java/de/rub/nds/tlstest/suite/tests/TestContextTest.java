package de.rub.nds.tlstest.suite.tests;

import de.rub.nds.tlstest.framework.TlsBaseTest;
import de.rub.nds.tlstest.framework.annotations.ClientTest;
import de.rub.nds.tlstest.framework.annotations.ServerTest;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.constants.TestEndpointType;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

@TlsTest
public class TestContextTest extends TlsBaseTest {

    @ServerTest
    void testServerTest() {
        assertEquals(context.getConfig().getTestEndpointMode(), TestEndpointType.SERVER);
    }

    @ClientTest
    void testClientTest() {
        assertEquals(context.getConfig().getTestEndpointMode(), TestEndpointType.CLIENT);
    }

    @Test
    void testBothTest() {
        assertEquals(context.getConfig().getTestEndpointMode(), TestEndpointType.SERVER);
    }
}


