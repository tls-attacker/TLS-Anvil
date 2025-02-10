/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.client.tls13.rfc8446;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.anvilcore.annotation.ClientTest;
import de.rub.nds.anvilcore.annotation.NonCombinatorialAnvilTest;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SupportedVersionsExtensionMessage;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
import de.rub.nds.tlstest.suite.tests.both.tls13.rfc8446.SharedExtensionTests;
import org.junit.jupiter.api.Tag;

@ClientTest
public class ClientHello extends Tls13Test {

    @NonCombinatorialAnvilTest(id = "8446-Agnoga6SCd")
    public void checkLegacyVersion() {
        ClientHelloMessage clientHello = context.getReceivedClientHelloMessage();
        byte[] version = clientHello.getProtocolVersion().getValue();
        SupportedVersionsExtensionMessage ext =
                clientHello.getExtension(SupportedVersionsExtensionMessage.class);
        assertArrayEquals(ProtocolVersion.TLS12.getValue(), version, "Invalid legacy_version");
        assertNotNull(ext, "Does not contain supported_versions extension");
    }

    @NonCombinatorialAnvilTest(id = "8446-eMuKxJmUfq")
    @Tag("new")
    public void checkExtensionsValidity() {
        ClientHelloMessage clientHello = context.getReceivedClientHelloMessage();
        checkForIllegalExtensions(clientHello);
        SharedExtensionTests.checkForDuplicateExtensions(clientHello);
    }

    @NonCombinatorialAnvilTest(id = "8446-u9JfnwgsWH")
    @Tag("new")
    public void checkMandatoryExtensions() {
        if (!context.getReceivedClientHelloMessage()
                .containsExtension(ExtensionType.PRE_SHARED_KEY)) {
            // consistency of Key Share and Named Groups Extension is evaluated by a test of the Key
            // Share class
            assertTrue(
                    context.getReceivedClientHelloMessage()
                            .containsExtension(ExtensionType.KEY_SHARE));
            assertTrue(
                    context.getReceivedClientHelloMessage()
                            .containsExtension(ExtensionType.ELLIPTIC_CURVES));
        }
    }

    private static void checkForIllegalExtensions(ClientHelloMessage clientHello) {
        assertNotNull(clientHello, "No ClientHello was received");
        // Clients MUST NOT use
        // cookies in their initial ClientHello in subsequent connections
        assertFalse(
                clientHello.containsExtension(ExtensionType.COOKIE),
                "Client sent a Cookie Extension in initial ClientHello");
        // Implementations MUST NOT use the Truncated HMAC extension
        assertFalse(
                clientHello.containsExtension(ExtensionType.TRUNCATED_HMAC),
                "Client sent a Truncated HMAC Extension");
    }

    @NonCombinatorialAnvilTest(id = "8446-Q2RbRWjAdJ")
    @Tag("new")
    public void checkLegacySessionId() {
        ClientHelloMessage clientHello = context.getReceivedClientHelloMessage();
        int sessionIdLength = clientHello.getSessionIdLength().getValue();
        if (sessionIdLength > 0) {
            assertEquals(
                    32, sessionIdLength, "Session ID was set by client but is not a 32-byte value");
        }
    }
}
