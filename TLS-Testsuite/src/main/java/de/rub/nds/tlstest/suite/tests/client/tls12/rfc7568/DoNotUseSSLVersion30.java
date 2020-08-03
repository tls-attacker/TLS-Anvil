package de.rub.nds.tlstest.suite.tests.client.tls12.rfc7568;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlstest.framework.annotations.ClientTest;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;

import static org.junit.Assert.assertNotEquals;

@RFC(number = 7568, section = "3")
@ClientTest
public class DoNotUseSSLVersion30 extends Tls12Test {

    @TlsTest(description = "SSLv3 MUST NOT be used. Negotiation of SSLv3 from " +
            "any version of TLS MUST NOT be permitted. " +
            "Pragmatically, clients MUST NOT send a ClientHello with " +
            "ClientHello.client_version set to {03,00}.", securitySeverity = SeverityLevel.HIGH)
    public void sendClientHelloVersion0300() {
        ClientHelloMessage clientHelloMessage = context.getReceivedClientHelloMessage();
        assertNotEquals("ClientHello contains protocol version 0300",
                ProtocolVersion.SSL3.getDeclaringClass(),
                clientHelloMessage.getProtocolVersion().getValue()
        );
    }
}
