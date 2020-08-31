package de.rub.nds.tlstest.suite.tests.client.tls13.rfc8446;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SupportedVersionsExtensionMessage;
import de.rub.nds.tlstest.framework.annotations.ClientTest;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;

import static org.junit.Assert.*;

@ClientTest
@RFC(number = 8446, section = "4.1.2 Client Hello")
public class ClientHello extends Tls13Test {

    @TlsTest(description = "In TLS 1.3, the client indicates its version preferences " +
            "in the \"supported_versions\" extension (Section 4.2.1) and the legacy_version " +
            "field MUST be set to 0x0303, which is the version number for TLS 1.2.", interoperabilitySeverity = SeverityLevel.HIGH)
    public void checkLegacyVersion() {
        ClientHelloMessage clientHello = context.getReceivedClientHelloMessage();
        byte[] version = clientHello.getProtocolVersion().getValue();
        SupportedVersionsExtensionMessage ext = clientHello.getExtension(SupportedVersionsExtensionMessage.class);
        assertArrayEquals("Invalid legacy_version", ProtocolVersion.TLS12.getValue(), version);
        assertNotNull("Does not contain supported_versions extension", ext);
    }

}
