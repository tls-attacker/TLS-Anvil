package de.rub.nds.tlstest.suite.tests.client.tls13.rfc8446;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.MaxFragmentLength;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import de.rub.nds.tlsattacker.core.protocol.message.extension.AlpnExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.HeartbeatExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.MaxFragmentLengthExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.ClientTest;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@RFC(number = 8446, section = "4.2 Extensions")
@ClientTest
public class Extensions extends Tls13Test {


    @TlsTest(description = "Implementations MUST NOT send extension responses if " +
            "the remote endpoint did not send the corresponding extension requests, " +
            "with the exception of the \"cookie\" extension in the HelloRetryRequest. " +
            "Upon receiving such an extension, an endpoint MUST abort " +
            "the handshake with an \"unsupported_extension\" alert.")
    public void sendAdditionalExtension(WorkflowRunner runner) {
        Config c = this.getConfig();
        runner.replaceSelectedCiphersuite = true;

        List<ExtensionType> extensions = new ArrayList<>(Arrays.asList(ExtensionType.values()));
        List<ExtensionType> clientExtensions = context.getReceivedClientHelloMessage().getExtensions().stream()
                .map(i -> ExtensionType.getExtensionType(i.getExtensionType().getValue()))
                .collect(Collectors.toList());
        extensions.removeAll(clientExtensions);

        WorkflowTrace workflowTrace = runner.generateWorkflowTraceUntilSendingMessage(WorkflowTraceType.HANDSHAKE, HandshakeMessageType.FINISHED);
        workflowTrace.addTlsActions(
                new SendAction(new FinishedMessage()),
                new ReceiveAction(new AlertMessage())
        );

        if (extensions.contains(ExtensionType.MAX_FRAGMENT_LENGTH)) {
            runner.setStateModifier(i -> {
                WorkflowTrace trace = i.getWorkflowTrace();
                MaxFragmentLengthExtensionMessage ext = new MaxFragmentLengthExtensionMessage();
                ext.setMaxFragmentLength(Modifiable.explicit(new byte[]{MaxFragmentLength.TWO_11.getValue()}));

                trace.getFirstSendMessage(EncryptedExtensionsMessage.class).addExtension(ext);
                return null;
            });
        }
        else if (extensions.contains(ExtensionType.ALPN)) {
            runner.setStateModifier(i -> {
                WorkflowTrace trace = i.getWorkflowTrace();
                AlpnExtensionMessage ext = new AlpnExtensionMessage(c);

                trace.getFirstSendMessage(EncryptedExtensionsMessage.class).addExtension(ext);
                return null;
            });
        }
        else {
            LOGGER.warn("ClientHello already contains every extension");
            throw new AssertionError("ClientHello already contains every extension");
        }

        runner.execute(workflowTrace, c).validateFinal(i -> {
            Validator.receivedFatalAlert(i);

            AlertMessage msg = i.getWorkflowTrace().getFirstReceivedMessage(AlertMessage.class);
            if (msg == null) return;

            Validator.testAlertDescription(i, AlertDescription.UNSUPPORTED_EXTENSION, msg);
        });
    }


    @TlsTest(description = "If an implementation receives an extension which it " +
            "recognizes and which is not specified for the message in " +
            "which it appears, it MUST abort the handshake with an \"illegal_parameter\" alert.", securitySeverity = SeverityLevel.MEDIUM)
    public void sendHeartBeatExtensionInSH(WorkflowRunner runner) {
        runner.replaceSelectedCiphersuite = true;
        Config c = this.getConfig();

        WorkflowTrace workflowTrace = runner.generateWorkflowTraceUntilSendingMessage(WorkflowTraceType.HANDSHAKE, HandshakeMessageType.FINISHED);
        workflowTrace.addTlsActions(
                new SendAction(new FinishedMessage()),
                new ReceiveAction(new AlertMessage())
        );

        runner.setStateModifier(i -> {
            WorkflowTrace trace = i.getWorkflowTrace();
            trace.getFirstSendMessage(ServerHelloMessage.class).addExtension(
                    new HeartbeatExtensionMessage()
            );
            return null;
        });

        runner.execute(workflowTrace, c).validateFinal(i -> {
            WorkflowTrace trace = i.getWorkflowTrace();
            Validator.receivedFatalAlert(i);

            AlertMessage msg = trace.getFirstReceivedMessage(AlertMessage.class);
            if (msg == null) return;
            Validator.testAlertDescription(i, AlertDescription.ILLEGAL_PARAMETER, msg);
        });
    }

    @TlsTest(description = "When multiple extensions of different " +
            "types are present, the extensions MAY appear " +
            "in any order, with the exception of \"pre_shared_key\" (Section 4.2.11) " +
            "which MUST be the last extension in the ClientHello " +
            "(but can appear anywhere in the ServerHello extensions block).")
    public void pskMustBeLastExtension() {
        ClientHelloMessage ch = context.getReceivedClientHelloMessage();
        if (ch.containsExtension(ExtensionType.PRE_SHARED_KEY)) {
            List<ExtensionMessage> extensions = ch.getExtensions();
            assertEquals("PSK Extensions is not last in list", ExtensionType.PRE_SHARED_KEY, extensions.get(extensions.size()-1).getExtensionTypeConstant());
        }
    }
}
