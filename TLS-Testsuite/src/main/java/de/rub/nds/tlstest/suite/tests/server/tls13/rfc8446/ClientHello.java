/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.server.tls13.rfc8446;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.GreaseExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.ServerTest;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.annotations.categories.Alert;
import de.rub.nds.tlstest.framework.annotations.categories.Compliance;
import de.rub.nds.tlstest.framework.annotations.categories.Crypto;
import de.rub.nds.tlstest.framework.annotations.categories.DeprecatedFeature;
import de.rub.nds.tlstest.framework.annotations.categories.Handshake;
import de.rub.nds.tlstest.framework.annotations.categories.Interoperability;
import de.rub.nds.tlstest.framework.annotations.categories.MessageStructure;
import de.rub.nds.tlstest.framework.annotations.categories.Security;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
import java.util.Arrays;
import static org.junit.Assert.assertFalse;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@ServerTest
@RFC(number = 8446, section = "4.1.2 Client Hello")
public class ClientHello extends Tls13Test {

    @TlsTest(description = "Because TLS 1.3 forbids renegotiation, if a server has negotiated "
            + "TLS 1.3 and receives a ClientHello at any other time, it MUST terminate the "
            + "connection with an \"unexpected_message\" alert.")
    @Handshake(SeverityLevel.MEDIUM)
    @Alert(SeverityLevel.MEDIUM)
    @Compliance(SeverityLevel.HIGH)
    //TODO MM: move to state machines?
    public void sendClientHelloAfterFinishedHandshake(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);

        WorkflowTrace trace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        trace.addTlsActions(
                new SendAction(new ClientHelloMessage(config)),
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(trace, config).validateFinal(i -> {
            Validator.receivedFatalAlert(i);

            AlertMessage alert = trace.getFirstReceivedMessage(AlertMessage.class);
            if (alert == null) {
                return;
            }
            Validator.testAlertDescription(i, AlertDescription.UNEXPECTED_MESSAGE, alert);
        });
    }

    @TlsTest(description = "If the list contains cipher suites that the server "
            + "does not recognize, support, or wish to use, the server MUST "
            + "ignore those cipher suites and process the remaining ones as "
            + "usual.")
    @Interoperability(SeverityLevel.CRITICAL)
    @Handshake(SeverityLevel.MEDIUM)
    @Compliance(SeverityLevel.CRITICAL)
    public void includeUnknownCipherSuite(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        ClientHelloMessage clientHelloMessage = new ClientHelloMessage(c);
        clientHelloMessage.setCipherSuites(Modifiable.insert(new byte[]{(byte) 0xfe, 0x00}, 0));

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);

        runner.execute(workflowTrace, c).validateFinal(Validator::executedAsPlanned);
    }

    @TlsTest(description = "In TLS 1.3, the client indicates its version preferences "
            + "in the \"supported_versions\" extension (Section 4.2.1) and the legacy_version "
            + "field MUST be set to 0x0303, which is the version number for TLS 1.2.")
    @Handshake(SeverityLevel.MEDIUM)
    @Compliance(SeverityLevel.HIGH)
    @Alert(SeverityLevel.MEDIUM)
    public void invalidLegacyVersion_higher(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);

        ClientHelloMessage msg = new ClientHelloMessage(config);
        msg.setProtocolVersion(Modifiable.explicit(new byte[]{0x03, 0x04}));

        WorkflowTrace trace = new WorkflowTrace();
        trace.addTlsActions(
                new SendAction(msg),
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(trace, config).validateFinal(Validator::receivedFatalAlert);
    }

    @TlsTest(description = "In TLS 1.3, the client indicates its version preferences "
            + "in the \"supported_versions\" extension (Section 4.2.1) and the legacy_version "
            + "field MUST be set to 0x0303, which is the version number for TLS 1.2.")
    @Handshake(SeverityLevel.MEDIUM)
    @Compliance(SeverityLevel.HIGH)
    @Alert(SeverityLevel.MEDIUM)
    public void invalidLegacyVersion_lower(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);

        ClientHelloMessage msg = new ClientHelloMessage(config);
        msg.setProtocolVersion(Modifiable.explicit(new byte[]{0x03, 0x02}));

        WorkflowTrace trace = new WorkflowTrace();
        trace.addTlsActions(
                new SendAction(msg),
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(trace, config).validateFinal(Validator::receivedFatalAlert);
    }

    @TlsTest(description = "Implementations MUST NOT send a "
            + "ClientHello.legacy_version or ServerHello.legacy_version "
            + "set to 0x0300 or less. Any endpoint receiving a Hello message with "
            + "ClientHello.legacy_version or ServerHello.legacy_version set to 0x0300 "
            + "MUST abort the handshake with a \"protocol_version\" alert.")
    @RFC(number = 8446, section = "D.5. Security Restrictions Related to Backward Compatibility")
    @Handshake(SeverityLevel.MEDIUM)
    @Compliance(SeverityLevel.HIGH)
    @Security(SeverityLevel.MEDIUM)
    @Alert(SeverityLevel.MEDIUM)
    public void invalidLegacyVersion_ssl30(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);

        ClientHelloMessage msg = new ClientHelloMessage(config);
        msg.setProtocolVersion(Modifiable.explicit(new byte[]{0x03, 0x00}));

        WorkflowTrace trace = new WorkflowTrace();
        trace.addTlsActions(
                new SendAction(msg),
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(trace, config).validateFinal(Validator::receivedFatalAlert);
    }

    @TlsTest(description = "For every TLS 1.3 ClientHello, this vector MUST contain "
            + "exactly one byte, set to zero, which corresponds to the \"null\" compression method in prior "
            + "versions of TLS. If a TLS 1.3 ClientHello is received with any other value in this field, "
            + "the server MUST abort the handshake with an \"illegal_parameter\" alert.")
    @Handshake(SeverityLevel.MEDIUM)
    @Compliance(SeverityLevel.HIGH)
    @Security(SeverityLevel.HIGH)
    @Alert(SeverityLevel.MEDIUM)
    public void invalidCompression(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);

        ClientHelloMessage msg = new ClientHelloMessage(config);
        msg.setCompressions(Modifiable.explicit(new byte[]{0x01}));

        WorkflowTrace trace = new WorkflowTrace();
        trace.addTlsActions(
                new SendAction(msg),
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(trace, config).validateFinal(i -> {
            Validator.receivedFatalAlert(i);

            AlertMessage alert = i.getWorkflowTrace().getFirstReceivedMessage(AlertMessage.class);
            if (alert == null) {
                return;
            }
            Validator.testAlertDescription(i, AlertDescription.ILLEGAL_PARAMETER, alert);
        });
    }

    @TlsTest(description = "Servers MUST ignore unrecognized extensions.")
    @Interoperability(SeverityLevel.CRITICAL)
    @Handshake(SeverityLevel.MEDIUM)
    @Compliance(SeverityLevel.CRITICAL)
    @Security(SeverityLevel.MEDIUM)
    public void includeUnknownExtension(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);

        //we use a Grease Extension for which we modify the type
        GreaseExtensionMessage greaseHelperExtension = new GreaseExtensionMessage(ExtensionType.GREASE_00, 32);
        greaseHelperExtension.setExtensionType(Modifiable.explicit(new byte[]{(byte) 0xBA, (byte) 0x9F}));

        ClientHelloMessage clientHello = (ClientHelloMessage) WorkflowTraceUtil.getFirstSendMessage(HandshakeMessageType.CLIENT_HELLO, workflowTrace);
        clientHello.addExtension(greaseHelperExtension);

        runner.execute(workflowTrace, config).validateFinal(i -> {
            Validator.executedAsPlanned(i);

            ServerHelloMessage serverHello = (ServerHelloMessage) WorkflowTraceUtil.getFirstReceivedMessage(HandshakeMessageType.SERVER_HELLO, workflowTrace);
            for (ExtensionMessage extension : serverHello.getExtensions()) {
                assertFalse("Server negotiated the undefined Extension", Arrays.equals(extension.getExtensionType().getValue(), greaseHelperExtension.getType().getValue()));
            }
        });
    }

}
