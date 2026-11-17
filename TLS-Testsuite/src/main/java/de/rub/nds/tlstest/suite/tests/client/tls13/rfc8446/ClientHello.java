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
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SupportedVersionsExtensionMessage;
import de.rub.nds.tlstest.framework.ClientFeatureExtractionResult;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
import de.rub.nds.tlstest.suite.tests.both.tls13.rfc8446.SharedExtensionTests;
import java.util.List;
import java.util.stream.Collectors;
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

    public static Boolean obsoleteGroup(NamedGroup group) {
        // This should ideally be part of TLS-Attacker instead of living here
        // Magic numbers from RFC 8446 B.3.1.4
        List<int[]> obsoleteRanges =
                List.of(
                        new int[] {0x0001, 0x0016},
                        new int[] {0x001A, 0x001C},
                        new int[] {0xFF01, 0xFF02});
        byte[] vBytes = group.getValue();
        int v = ((vBytes[0] & 0xFF) << 8) | (vBytes[1] & 0xFF);
        return obsoleteRanges.stream().anyMatch(range -> v >= range[0] && v <= range[1]);
    }

    @NonCombinatorialAnvilTest(id = "8446-b62d9f0a31")
    @Tag("rfc8446-coverage")
    public void doesNotOfferObsoleteNamedGroups() {
        // Counterpart: 8446-h8L9m2QvKx
        ClientFeatureExtractionResult extractionResult =
                (ClientFeatureExtractionResult) context.getFeatureExtractionResult();
        if (extractionResult.getClientHelloNamedGroups() != null) {
            List<NamedGroup> obsoleteGroupsOffered =
                    extractionResult.getClientHelloNamedGroups().stream()
                            .filter(ClientHello::obsoleteGroup)
                            .collect(Collectors.toList());

            assertTrue(
                    obsoleteGroupsOffered.isEmpty(),
                    "Client offered deprecated groups: "
                            + obsoleteGroupsOffered.stream()
                                    .map(
                                            group -> {
                                                byte[] value = group.getValue();
                                                return String.format(
                                                        "%s (0x%02X%02X)",
                                                        group, value[0], value[1]);
                                            })
                                    .collect(Collectors.joining(",")));
        }
    }
}
