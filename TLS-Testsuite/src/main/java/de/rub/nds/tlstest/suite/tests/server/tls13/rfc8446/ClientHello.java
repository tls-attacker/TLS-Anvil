/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.server.tls13.rfc8446;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.EnforcedSenderRestriction;
import de.rub.nds.anvilcore.annotation.ExcludeParameter;
import de.rub.nds.anvilcore.annotation.ServerTest;
import de.rub.nds.anvilcore.teststate.AnvilTestCase;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.EncryptedExtensionsMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.cert.CertificateEntry;
import de.rub.nds.tlsattacker.core.protocol.message.extension.CertificateStatusRequestV2ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.GreaseExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.statusrequestv2.RequestItemV2;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceConfigurationUtil;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceResultUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Tag;

@ServerTest
public class ClientHello extends Tls13Test {

    @AnvilTest(id = "8446-Ruhj2eLN2t")
    public void includeUnknownCipherSuite(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);

        ClientHelloMessage clientHelloMessage = new ClientHelloMessage(c);
        clientHelloMessage.setCipherSuites(Modifiable.insert(new byte[] {(byte) 0xfe, 0x00}, 0));

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);

        State state = runner.execute(workflowTrace, c);
        Validator.executedAsPlanned(state, testCase);
    }

    @AnvilTest(id = "8446-B41SD1Cnr6")
    @EnforcedSenderRestriction
    public void invalidLegacyVersion_higher(AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);

        ClientHelloMessage msg = new ClientHelloMessage(config);
        msg.setProtocolVersion(Modifiable.explicit(new byte[] {0x03, 0x04}));

        WorkflowTrace trace = new WorkflowTrace();
        trace.addTlsActions(new SendAction(msg), new ReceiveAction(new AlertMessage()));

        State state = runner.execute(trace, config);
        Validator.receivedFatalAlert(state, testCase);
    }

    @AnvilTest(id = "8446-fsDXt1hint")
    @EnforcedSenderRestriction
    public void invalidLegacyVersion_lower(AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);

        ClientHelloMessage msg = new ClientHelloMessage(config);
        msg.setProtocolVersion(Modifiable.explicit(new byte[] {0x03, 0x02}));

        WorkflowTrace trace = new WorkflowTrace();
        trace.addTlsActions(new SendAction(msg), new ReceiveAction(new AlertMessage()));

        State state = runner.execute(trace, config);
        Validator.receivedFatalAlert(state, testCase);
    }

    @AnvilTest(id = "8446-hsFoi24Gdh")
    public void invalidLegacyVersion_ssl30(AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);

        ClientHelloMessage msg = new ClientHelloMessage(config);
        msg.setProtocolVersion(Modifiable.explicit(new byte[] {0x03, 0x00}));

        WorkflowTrace trace = new WorkflowTrace();
        trace.addTlsActions(new SendAction(msg), new ReceiveAction(new AlertMessage()));

        State state = runner.execute(trace, config);
        Validator.receivedFatalAlert(state, testCase);
    }

    @AnvilTest(id = "8446-qgJEM4UoBe")
    public void invalidCompression(AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);

        ClientHelloMessage msg = new ClientHelloMessage(config);
        msg.setCompressions(Modifiable.explicit(new byte[] {0x01}));

        WorkflowTrace trace = new WorkflowTrace();
        trace.addTlsActions(new SendAction(msg), new ReceiveAction(new AlertMessage()));

        State state = runner.execute(trace, config);

        Validator.receivedFatalAlert(state, testCase, AlertDescription.ILLEGAL_PARAMETER);
    }

    @AnvilTest(id = "8446-vtJcLUKtNv")
    public void includeUnknownExtension(AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);

        // we use a Grease Extension for which we modify the type
        GreaseExtensionMessage greaseHelperExtension =
                new GreaseExtensionMessage(ExtensionType.GREASE_00, 32);
        greaseHelperExtension.setExtensionType(
                Modifiable.explicit(new byte[] {(byte) 0xBA, (byte) 0x9F}));

        ClientHelloMessage clientHello =
                (ClientHelloMessage)
                        WorkflowTraceConfigurationUtil.getFirstStaticConfiguredSendMessage(
                                workflowTrace, HandshakeMessageType.CLIENT_HELLO);
        clientHello.addExtension(greaseHelperExtension);

        State state = runner.execute(workflowTrace, config);

        Validator.executedAsPlanned(state, testCase);

        ServerHelloMessage serverHello =
                (ServerHelloMessage)
                        WorkflowTraceResultUtil.getFirstReceivedMessage(
                                workflowTrace, HandshakeMessageType.SERVER_HELLO);
        for (ExtensionMessage extension : serverHello.getExtensions()) {
            assertFalse(
                    Arrays.equals(
                            extension.getExtensionType().getValue(),
                            greaseHelperExtension.getType().getValue()),
                    "Server negotiated the undefined Extension");
        }
    }

    // there is an omitSignatureAlgorithms test in SignatureAlgorithms

    @AnvilTest(id = "8446-GZpjQTKUD4")
    @ExcludeParameter("NAMED_GROUP")
    @Tag("new")
    public void omitKeyShareAndSupportedGroups(AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);
        config.setAddKeyShareExtension(false);
        config.setAddEllipticCurveExtension(false);

        performMissingExtensionTest(config, runner, testCase);
    }

    private void performMissingExtensionTest(
            Config config, WorkflowRunner runner, AnvilTestCase testCase) {
        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));

        State state = runner.execute(workflowTrace, config);

        Validator.receivedFatalAlert(state, testCase, AlertDescription.MISSING_EXTENSION);
    }

    @AnvilTest(id = "8446-jEEunwNUJ3")
    @ExcludeParameter("NAMED_GROUP")
    @Tag("new")
    public void omitKeyShare(AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);
        config.setAddKeyShareExtension(false);

        performMissingExtensionTest(config, runner, testCase);
    }

    @AnvilTest(id = "8446-KQn4u3Xj4M")
    @Tag("new")
    public void omitSupportedGroups(AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);
        config.setAddEllipticCurveExtension(false);

        performMissingExtensionTest(config, runner, testCase);
    }

    @AnvilTest(id = "8446-2de9de9e4a")
    @Tag("rfc8446-coverage")
    public void sendStatusRequestExtension(AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);
        config.setStatusRequestV2RequestList(List.of(new RequestItemV2(1, 4, 0, 0, new byte[0])));

        WorkflowTrace trace = runner.generateWorkflowTrace(WorkflowTraceType.DYNAMIC_HELLO);
        // add the deprecated status_request_v2 extension to the ClientHello
        ClientHelloMessage msg =
                (ClientHelloMessage)
                        WorkflowTraceConfigurationUtil.getFirstStaticConfiguredSendMessage(
                                trace, HandshakeMessageType.CLIENT_HELLO);
        msg.addExtension(new CertificateStatusRequestV2ExtensionMessage());

        State state = runner.execute(trace, config);

        // RFC 8446 4.4.2.1: TLS 1.3 servers MUST NOT act upon the presence of
        // status_request_v2 and MUST be able to process a ClientHello that
        // includes it, so the handshake completes without a fatal alert.
        Validator.executedAsPlanned(state, testCase);

        // assert that the server did not send a status_request_v2 extension in
        // - EncryptedExtensions
        // - CertificateRequest
        // - CertificateEntry extensions
        List<Class<? extends HandshakeMessage>> messageClasses =
                List.of(EncryptedExtensionsMessage.class, CertificateRequestMessage.class);
        for (Class<? extends HandshakeMessage> mClass : messageClasses) {
            HandshakeMessage message = state.getWorkflowTrace().getLastReceivedMessage(mClass);
            if (message == null || message.getExtensions() == null) {
                // message was not part of the handshake or carries no top-level
                // extensions, nothing to check
                continue;
            }
            List<ExtensionMessage> extensions =
                    message.getExtensions().stream()
                            .filter(CertificateStatusRequestV2ExtensionMessage.class::isInstance)
                            .toList();
            assertTrue(
                    extensions.isEmpty(),
                    "Server sent a status_request_v2 extension in " + mClass.getSimpleName());
        }

        CertificateMessage certificate =
                state.getWorkflowTrace().getLastReceivedMessage(CertificateMessage.class);
        if (certificate != null) {
            assertNotNull(
                    certificate.getCertificateEntryList(), "Certificate entries were not parsed");
            for (CertificateEntry entry : certificate.getCertificateEntryList()) {
                assertNotNull(
                        entry.getExtensionList(), "Certificate entry extensions were not parsed");
                assertTrue(
                        entry.getExtensionList().stream()
                                .noneMatch(
                                        CertificateStatusRequestV2ExtensionMessage.class
                                                ::isInstance),
                        "Server sent a status_request_v2 extension in a CertificateEntry");
            }
        }
    }

    @AnvilTest(id = "8446-Uqrk3dnMz7")
    @KeyExchange(supported = KeyExchangeType.ALL12)
    @Tag("new")
    public void acceptsCompressionListForLegacyClient(
            AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = prepareConfig(context.getConfig().createConfig(), runner);
        config.setDefaultClientSupportedCompressionMethods(
                CompressionMethod.NULL, CompressionMethod.DEFLATE);
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        State state = runner.execute(workflowTrace, config);
        Validator.executedAsPlanned(state, testCase);
    }

    @AnvilTest(id = "8446-h8L9m2QvKx")
    @Tag("rfc8446-coverage")
    public void doesNotNegotiateObsoleteNamedGroups(AnvilTestCase testCase, WorkflowRunner runner) {
        List<NamedGroup> obsoleteGroups =
                NamedGroup.getImplemented().stream()
                        .filter(g -> g != null)
                        .filter(
                                de.rub.nds.tlstest.suite.tests.client.tls13.rfc8446.ClientHello
                                        ::obsoleteGroup)
                        .collect(Collectors.toList());

        assertFalse(obsoleteGroups.isEmpty());
        Config config = getPreparedConfig(runner);
        config.setDefaultClientNamedGroups(obsoleteGroups);
        config.setDefaultClientKeyShareNamedGroups(obsoleteGroups);
        testCase.addAdditionalResultInfo(
                "Anvil ClientHello offered only obsolete groups: "
                        + obsoleteGroups.stream()
                                .map(
                                        group -> {
                                            byte[] value = group.getValue();
                                            return String.format(
                                                    "%s (0x%02X%02X)", group, value[0], value[1]);
                                        })
                                .collect(Collectors.joining(",")));

        WorkflowTrace workflowTrace = new WorkflowTrace();
        ClientHelloMessage clientHello = new ClientHelloMessage(config);
        workflowTrace.addTlsActions(
                new SendAction(clientHello), new ReceiveAction(new AlertMessage()));
        State state = runner.execute(workflowTrace, config);

        String response =
                Validator.getMessagesOfLastReceive(state).stream()
                        .map(message -> message.toCompactString())
                        .collect(Collectors.joining(","));
        testCase.addAdditionalResultInfo(
                "Server response to Anvil's obsolete-only named groups offer: "
                        + (response.isEmpty() ? "no TLS messages received" : response));

        // RFC 8446 section 4.1.1: If there is no overlap between the received
        //   "supported_groups" and the groups supported by the server, then the
        //   server MUST abort the handshake with a "handshake_failure" or an
        //   "insufficient_security" alert.
        //
        // The obsolete_RESERVED rule itself names no alert.
        Validator.receivedFatalAlert(
                state,
                testCase,
                AlertDescription.HANDSHAKE_FAILURE,
                AlertDescription.INSUFFICIENT_SECURITY);
    }
}
