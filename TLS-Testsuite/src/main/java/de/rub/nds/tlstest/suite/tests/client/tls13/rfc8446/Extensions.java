/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.client.tls13.rfc8446;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.MaxFragmentLength;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.EncryptedExtensionsMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.AlpnExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.HeartbeatExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.MaxFragmentLengthExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerNameIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.ClientTest;
import de.rub.nds.tlstest.framework.annotations.ExplicitValues;
import de.rub.nds.tlstest.framework.annotations.ManualConfig;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.ScopeExtensions;
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
import de.rub.nds.tlstest.framework.model.DerivationScope;
import de.rub.nds.tlstest.framework.model.DerivationType;
import de.rub.nds.tlstest.framework.model.derivationParameter.DerivationParameter;
import de.rub.nds.tlstest.framework.model.derivationParameter.ExtensionDerivation;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;

import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@RFC(number = 8446, section = "4.2 Extensions")
@ClientTest
public class Extensions extends Tls13Test {

    public List<DerivationParameter> getUnrequestedExtensions(DerivationScope scope) {
        List<DerivationParameter> parameterValues = new LinkedList<>();
        List<ExtensionType> extensions = new LinkedList<>();
        extensions.add(ExtensionType.SERVER_NAME_INDICATION);
        extensions.add(ExtensionType.MAX_FRAGMENT_LENGTH);
        extensions.add(ExtensionType.ALPN);
        List<ExtensionType> clientExtensions = context.getReceivedClientHelloMessage().getExtensions().stream()
                .map(i -> ExtensionType.getExtensionType(i.getExtensionType().getValue()))
                .collect(Collectors.toList());
        extensions.removeAll(clientExtensions);

        for (ExtensionType unrequestedType : extensions) {
            parameterValues.add(new ExtensionDerivation(unrequestedType));
        }

        return parameterValues;
    }

    @TlsTest(description = "Implementations MUST NOT send extension responses if "
            + "the remote endpoint did not send the corresponding extension requests, "
            + "with the exception of the \"cookie\" extension in the HelloRetryRequest. "
            + "Upon receiving such an extension, an endpoint MUST abort "
            + "the handshake with an \"unsupported_extension\" alert.")
    @ScopeExtensions(DerivationType.EXTENSION)
    @ManualConfig(DerivationType.EXTENSION)
    @ExplicitValues(affectedTypes = DerivationType.EXTENSION, methods = "getUnrequestedExtensions")
    @Interoperability(SeverityLevel.HIGH)
    @Handshake(SeverityLevel.MEDIUM)
    @Alert(SeverityLevel.MEDIUM)
    @Compliance(SeverityLevel.MEDIUM)
    public void sendAdditionalExtension(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        ExtensionType selectedExtension = derivationContainer.getDerivation(ExtensionDerivation.class).getSelectedValue();

        List<ExtensionType> extensions = new ArrayList<>(Arrays.asList(ExtensionType.values()));
        List<ExtensionType> clientExtensions = context.getReceivedClientHelloMessage().getExtensions().stream()
                .map(i -> ExtensionType.getExtensionType(i.getExtensionType().getValue()))
                .collect(Collectors.toList());
        extensions.removeAll(clientExtensions);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsActions(
                new ReceiveAction(new AlertMessage())
        );

        if (selectedExtension == ExtensionType.MAX_FRAGMENT_LENGTH) {
            MaxFragmentLengthExtensionMessage ext = new MaxFragmentLengthExtensionMessage();
            ext.setMaxFragmentLength(Modifiable.explicit(new byte[]{MaxFragmentLength.TWO_11.getValue()}));

            workflowTrace.getFirstSendMessage(EncryptedExtensionsMessage.class).addExtension(ext);
        } else if (selectedExtension == ExtensionType.ALPN) {
            c.setDefaultProposedAlpnProtocols("http/1.1", "spdy/1", "spdy/2", "spdy/3", "stun.turn",
                    "stun.nat-discovery", "h2", "h2c", "webrtc", "c-webrtc", "ftp", "imap", "pop3", "managesieve");
            AlpnExtensionMessage ext = new AlpnExtensionMessage(c);
            workflowTrace.getFirstSendMessage(EncryptedExtensionsMessage.class).addExtension(ext);
        } else if (selectedExtension == ExtensionType.SERVER_NAME_INDICATION) {
            ServerNameIndicationExtensionMessage ext = new ServerNameIndicationExtensionMessage();
            workflowTrace.getFirstSendMessage(EncryptedExtensionsMessage.class).addExtension(ext);
        } else {
            LOGGER.warn("ClientHello already contains every extension");
            throw new AssertionError("ClientHello already contains every extension");
        }

        runner.execute(workflowTrace, c).validateFinal(i -> {
            Validator.receivedFatalAlert(i);

            AlertMessage msg = i.getWorkflowTrace().getFirstReceivedMessage(AlertMessage.class);
            if (msg == null) {
                return;
            }

            Validator.testAlertDescription(i, AlertDescription.UNSUPPORTED_EXTENSION, msg);
        });
    }

    @TlsTest(description = "If an implementation receives an extension which it "
            + "recognizes and which is not specified for the message in "
            + "which it appears, it MUST abort the handshake with an \"illegal_parameter\" alert.")
    @Interoperability(SeverityLevel.HIGH)
    @Handshake(SeverityLevel.MEDIUM)
    @Alert(SeverityLevel.MEDIUM)
    @Compliance(SeverityLevel.MEDIUM)
    public void sendHeartBeatExtensionInSH(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsActions(
                new ReceiveAction(new AlertMessage())
        );

        workflowTrace.getFirstSendMessage(ServerHelloMessage.class).addExtension(
                new HeartbeatExtensionMessage()
        );

        runner.execute(workflowTrace, c).validateFinal(i -> {
            WorkflowTrace trace = i.getWorkflowTrace();
            Validator.receivedFatalAlert(i);

            AlertMessage msg = trace.getFirstReceivedMessage(AlertMessage.class);
            if (msg == null) {
                return;
            }
            Validator.testAlertDescription(i, AlertDescription.ILLEGAL_PARAMETER, msg);
        });
    }
}
