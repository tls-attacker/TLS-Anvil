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
import de.rub.nds.tlsattacker.core.constants.MaxFragmentLength;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.EncryptedExtensionsMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.MaxFragmentLengthExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PaddingExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SupportedVersionsExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.ClientTest;
import de.rub.nds.tlstest.framework.annotations.MethodCondition;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;

@ClientTest
@RFC(number = 8446, section = "4.3.1. Encrypted Extensions")
public class EncryptedExtensions extends Tls13Test {

    public ConditionEvaluationResult sentMaximumFragmentLength() {
        if (context.getReceivedClientHelloMessage().getExtension(MaxFragmentLengthExtensionMessage.class) != null) {
            return ConditionEvaluationResult.enabled("");
        }
        return ConditionEvaluationResult.disabled("Client does not support maximum fragment length");
    }
    
    private MaxFragmentLength getUnrequestedMaxFragLen(MaxFragmentLengthExtensionMessage req) {
        for(MaxFragmentLength len: MaxFragmentLength.values()) {
            if(req.getMaxFragmentLength().getValue()[0] != len.getValue()) {
                return len;
            }
        }
        return MaxFragmentLength.TWO_11;
    }
    
    @TlsTest(description = "The client MUST check EncryptedExtensions " +
            "for the presence of any forbidden extensions and if " +
            "any are found MUST abort the handshake " +
            "with an \"illegal_parameter\" alert.", interoperabilitySeverity = SeverityLevel.MEDIUM)
    public void sendSupportedVersionsExtensionInEE(WorkflowRunner runner) {
        runner.replaceSelectedCiphersuite = true;

        Config c = this.getConfig();
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsActions(new ReceiveAction(new AlertMessage()));

        runner.setStateModifier(i -> {
            WorkflowTrace trace = i.getWorkflowTrace();
            EncryptedExtensionsMessage ee = trace.getFirstSendMessage(EncryptedExtensionsMessage.class);
            ee.addExtension(new SupportedVersionsExtensionMessage());
            return null;
        });

        runner.execute(workflowTrace, c).validateFinal(i -> {
            Validator.receivedFatalAlert(i);
            AlertMessage alert = i.getWorkflowTrace().getFirstReceivedMessage(AlertMessage.class);
            if (alert == null) return;
            Validator.testAlertDescription(i, AlertDescription.ILLEGAL_PARAMETER, alert);
        });
    }

    @TlsTest(description = "The client MUST check EncryptedExtensions " +
            "for the presence of any forbidden extensions and if " +
            "any are found MUST abort the handshake " +
            "with an \"illegal_parameter\" alert.", interoperabilitySeverity = SeverityLevel.MEDIUM)
    public void sendPaddingExtensionInEE(WorkflowRunner runner) {
        runner.replaceSelectedCiphersuite = true;

        Config c = this.getConfig();
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsActions(new ReceiveAction(new AlertMessage()));

        runner.setStateModifier(i -> {
            WorkflowTrace trace = i.getWorkflowTrace();
            EncryptedExtensionsMessage ee = trace.getFirstSendMessage(EncryptedExtensionsMessage.class);
            ee.addExtension(new PaddingExtensionMessage());
            return null;
        });

        runner.execute(workflowTrace, c).validateFinal(i -> {
            Validator.receivedFatalAlert(i);
            AlertMessage alert = i.getWorkflowTrace().getFirstReceivedMessage(AlertMessage.class);
            if (alert == null) return;
            Validator.testAlertDescription(i, AlertDescription.ILLEGAL_PARAMETER, alert);
        });
    }
    
    @RFC(number = 6066, section = "4. Maximum Fragment Length Negotiation")
    @TlsTest(description = "Similarly, if a client receives a maximum fragment length negotiation " +
            "response that differs from the length it requested, it MUST also abort the handshake with an \"illegal_parameter\" alert.")
    @MethodCondition(method = "sentMaximumFragmentLength")
    public void invalidMaximumFragmentLength(WorkflowRunner runner) {
        Config c = this.getConfig();
        runner.replaceSelectedCiphersuite = true;

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsActions(
                new ReceiveAction(new AlertMessage())
        );

        runner.setStateModifier(i -> {
            WorkflowTrace trace = i.getWorkflowTrace();
            EncryptedExtensionsMessage encExt = trace.getFirstSendMessage(EncryptedExtensionsMessage.class);
            MaxFragmentLengthExtensionMessage malMaxFrag = new MaxFragmentLengthExtensionMessage();
            malMaxFrag.setMaxFragmentLength(Modifiable.explicit(new byte[]{5}));
            encExt.addExtension(malMaxFrag);
            return null;
        });

        runner.execute(workflowTrace, c).validateFinal(i -> {
            Validator.receivedFatalAlert(i);

            WorkflowTrace trace = i.getWorkflowTrace();
            AlertMessage alert = trace.getLastReceivedMessage(AlertMessage.class);
            if (alert == null) return;

            Validator.testAlertDescription(i, AlertDescription.ILLEGAL_PARAMETER, alert);
        });
    }
    
    @TlsTest(description = "Similarly, if a client receives a maximum fragment length negotiation " +
            "response that differs from the length it requested, it MUST also abort the handshake with an \"illegal_parameter\" alert.")
    @MethodCondition(method = "sentMaximumFragmentLength")
    public void unrequestedMaximumFragmentLength(WorkflowRunner runner) {
        Config c = this.getConfig();
        runner.replaceSelectedCiphersuite = true;
        c.setAddMaxFragmentLengthExtension(true);
        
        MaxFragmentLength unreqLen = getUnrequestedMaxFragLen(context.getReceivedClientHelloMessage().getExtension(MaxFragmentLengthExtensionMessage.class));

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsActions(
                new ReceiveAction(new AlertMessage())
        );

        runner.setStateModifier(i -> {
            WorkflowTrace trace = i.getWorkflowTrace();
            EncryptedExtensionsMessage encExt = trace.getFirstSendMessage(EncryptedExtensionsMessage.class);
            MaxFragmentLengthExtensionMessage malMaxFrag = new MaxFragmentLengthExtensionMessage();
            malMaxFrag.setMaxFragmentLength(Modifiable.explicit(new byte[]{unreqLen.getValue()}));
            encExt.addExtension(malMaxFrag);
            return null;
        });

        runner.execute(workflowTrace, c).validateFinal(i -> {
            Validator.receivedFatalAlert(i);

            WorkflowTrace trace = i.getWorkflowTrace();
            AlertMessage alert = trace.getLastReceivedMessage(AlertMessage.class);
            if (alert == null) return;

            Validator.testAlertDescription(i, AlertDescription.ILLEGAL_PARAMETER, alert);
        });
    }
}
