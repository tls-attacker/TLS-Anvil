/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.client.tls13.rfc8446;

import static org.junit.Assert.*;

import de.rub.nds.anvilcore.annotation.TestDescription;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SupportedVersionsExtensionMessage;
import de.rub.nds.tlstest.framework.annotations.ClientTest;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.categories.ComplianceCategory;
import de.rub.nds.tlstest.framework.annotations.categories.HandshakeCategory;
import de.rub.nds.tlstest.framework.annotations.categories.InteroperabilityCategory;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
import de.rub.nds.tlstest.suite.tests.both.tls13.rfc8446.SharedExtensionTests;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

@ClientTest
@RFC(number = 8446, section = "4.1.2 Client Hello")
public class ClientHello extends Tls13Test {

    @Test
    @TestDescription(
            "In "
                    + "TLS 1.3, the client indicates its version preferences in the "
                    + "\"supported_versions\" extension (Section 4.2.1) and the "
                    + "legacy_version field MUST be set to 0x0303, which is the version "
                    + "number for TLS 1.2.  TLS 1.3 ClientHellos are identified as having "
                    + "a legacy_version of 0x0303 and a supported_versions extension "
                    + "present with 0x0304 as the highest version indicated therein.")
    @InteroperabilityCategory(SeverityLevel.MEDIUM)
    @HandshakeCategory(SeverityLevel.LOW)
    @ComplianceCategory(SeverityLevel.LOW)
    public void checkLegacyVersion() {
        ClientHelloMessage clientHello = context.getReceivedClientHelloMessage();
        byte[] version = clientHello.getProtocolVersion().getValue();
        SupportedVersionsExtensionMessage ext =
                clientHello.getExtension(SupportedVersionsExtensionMessage.class);
        assertArrayEquals("Invalid legacy_version", ProtocolVersion.TLS12.getValue(), version);
        assertNotNull("Does not contain supported_versions extension", ext);
    }

    @Test
    @TestDescription(
            "There MUST NOT be more than one extension of the "
                    + "same type in a given extension block. [...]"
                    + "Clients MUST NOT use "
                    + "cookies in their initial ClientHello in subsequent connections. [...]"
                    + "Implementations MUST NOT use the Truncated HMAC extension")
    @RFC(
            number = 8446,
            section =
                    "4.2.  Extensions, 4.2.2.  Cookie, and D.5.  Security Restrictions Related to Backward Compatibility")
    @InteroperabilityCategory(SeverityLevel.CRITICAL)
    @HandshakeCategory(SeverityLevel.CRITICAL)
    @ComplianceCategory(SeverityLevel.CRITICAL)
    @Tag("new")
    public void checkExtensionsValidity() {
        ClientHelloMessage clientHello = context.getReceivedClientHelloMessage();
        checkForIllegalExtensions(clientHello);
        SharedExtensionTests.checkForDuplicateExtensions(clientHello);
    }

    @Test
    @TestDescription(
            "A client is considered to be attempting to negotiate using this "
                    + "specification if the ClientHello contains a \"supported_versions\" "
                    + "extension with 0x0304 contained in its body.  Such a ClientHello "
                    + "message MUST meet the following requirements: [...]"
                    + "If not containing a \"pre_shared_key\" extension, it MUST contain "
                    + "both a \"signature_algorithms\" extension and a \"supported_groups\" "
                    + "extension. [...]"
                    + "If containing a \"supported_groups\" extension, it MUST also contain "
                    + "a \"key_share\" extension, and vice versa.  An empty "
                    + "KeyShare.client_shares vector is permitted.")
    @InteroperabilityCategory(SeverityLevel.CRITICAL)
    @HandshakeCategory(SeverityLevel.CRITICAL)
    @ComplianceCategory(SeverityLevel.CRITICAL)
    @RFC(number = 8446, section = "9.2.  Mandatory-to-Implement Extensions")
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
        assertNotNull("No ClientHello was received", clientHello);
        // Clients MUST NOT use
        // cookies in their initial ClientHello in subsequent connections
        assertFalse(
                "Client sent a Cookie Extension in initial ClientHello",
                clientHello.containsExtension(ExtensionType.COOKIE));
        // Implementations MUST NOT use the Truncated HMAC extension
        assertFalse(
                "Client sent a Truncated HMAC Extension",
                clientHello.containsExtension(ExtensionType.TRUNCATED_HMAC));
    }

    @Test
    @TestDescription(
            "In compatibility mode (see Appendix D.4), "
                    + "this field MUST be non-empty, so a client not offering a "
                    + "pre-TLS 1.3 session MUST generate a new 32-byte value.  This value "
                    + "need not be random but SHOULD be unpredictable to avoid "
                    + "implementations fixating on a specific value (also known as "
                    + "ossification).  Otherwise, it MUST be set as a zero-length vector "
                    + "(i.e., a zero-valued single byte length field).")
    @InteroperabilityCategory(SeverityLevel.CRITICAL)
    @HandshakeCategory(SeverityLevel.CRITICAL)
    @ComplianceCategory(SeverityLevel.CRITICAL)
    @Tag("new")
    public void checkLegacySessionId() {
        ClientHelloMessage clientHello = context.getReceivedClientHelloMessage();
        int sessionIdLength = clientHello.getSessionIdLength().getValue();
        if (sessionIdLength > 0) {
            assertEquals(
                    "Session ID was set by client but is not a 32-byte value", 32, sessionIdLength);
        }
    }
}
