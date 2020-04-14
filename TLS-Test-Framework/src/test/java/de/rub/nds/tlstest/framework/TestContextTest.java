package de.rub.nds.tlstest.framework;

import de.rub.nds.tlstest.framework.annotations.ClientTest;
import de.rub.nds.tlstest.framework.annotations.ServerTest;
import de.rub.nds.tlstest.framework.constants.TestEndpointType;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class TestContextTest extends TlsBaseTest {

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
        assertEquals(context.getConfig().getTestEndpointMode(), TestEndpointType.BOTH);
    }
}

@ServerTest
class TestServerClassContext extends TlsBaseTest {

    @Test
    void testServerTest() {
        assertEquals(context.getConfig().getTestEndpointMode(), TestEndpointType.SERVER);
    }

    @ClientTest
    void testClientTest() {
        assertEquals(context.getConfig().getTestEndpointMode(), TestEndpointType.CLIENT);
    }
}


@ClientTest
class TestClientClassContext extends TlsBaseTest {

    @Test
    void testServerTest() {
        assertEquals(context.getConfig().getTestEndpointMode(), TestEndpointType.CLIENT);
    }

    @ServerTest
    void testClientTest() {
        assertEquals(context.getConfig().getTestEndpointMode(), TestEndpointType.SERVER);
    }
}