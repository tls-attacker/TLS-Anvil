package de.rub.nds.tlstest.suite.tests.both.tls12.rfc5246;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ChangePrfAlgorithmAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.constants.AssertMsgs;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;

import static org.junit.Assert.assertTrue;

@RFC(number = 5246, section = "7.4.9 Finished")
public class Finished extends Tls12Test {

    @TlsTest(description = "Recipients of Finished messages MUST verify that the contents are correct.", securitySeverity = SeverityLevel.CRITICAL)
    public void verifyFinishedMessageCorrect(WorkflowRunner runner) {
        Config c = this.getConfig();
        runner.replaceSupportedCiphersuites = true;
        runner.replaceSelectedCiphersuite = true;

        FinishedMessage finishedMessage = new FinishedMessage();
        finishedMessage.setVerifyData(Modifiable.xor(new byte[]{0x01}, 0));

        WorkflowTrace workflowTrace = runner.generateWorkflowTraceUntilSendingMessage(WorkflowTraceType.HANDSHAKE, HandshakeMessageType.FINISHED);
        workflowTrace.addTlsActions(
                new SendAction(finishedMessage),
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(workflowTrace, c).validateFinal(i -> {
            WorkflowTrace trace = i.getWorkflowTrace();
            assertTrue(AssertMsgs.WorkflowNotExecuted, trace.executedAsPlanned());

            Validator.receivedFatalAlert(i);
        });
    }

    @TlsTest(description = "For the PRF defined in Section 5, the Hash MUST be the Hash used as the basis for the PRF.", securitySeverity = SeverityLevel.CRITICAL)
    public void invalidPRF(WorkflowRunner runner) {
        Config c = this.getConfig();
        runner.replaceSupportedCiphersuites = true;
        runner.replaceSelectedCiphersuite = true;

        WorkflowTrace workflowTrace = runner.generateWorkflowTraceUntilSendingMessage(WorkflowTraceType.HANDSHAKE, HandshakeMessageType.FINISHED);
        workflowTrace.addTlsActions(
                new ChangePrfAlgorithmAction(),
                new SendAction(new FinishedMessage()),
                new ReceiveAction(new AlertMessage())
        );

        runner.setStateModifier(i -> {
            ChangePrfAlgorithmAction action = i.getWorkflowTrace().getFirstAction(ChangePrfAlgorithmAction.class);
            CipherSuite cipherSuite = i.getInspectedCipherSuite();

            PRFAlgorithm alg = AlgorithmResolver.getPRFAlgorithm(ProtocolVersion.TLS12, cipherSuite);
            if (alg == PRFAlgorithm.TLS_PRF_SHA256) {
                action.setNewValue(PRFAlgorithm.TLS_PRF_SHA384);
            } else {
                action.setNewValue(PRFAlgorithm.TLS_PRF_SHA256);
            }
            return null;
        });

        runner.execute(workflowTrace, c).validateFinal(i -> {
            WorkflowTrace trace = i.getWorkflowTrace();
            assertTrue(AssertMsgs.WorkflowNotExecuted, trace.executedAsPlanned());

            Validator.receivedFatalAlert(i);
        });
    }

    @TlsTest(description = "It is a fatal error if a Finished message is not preceded by a ChangeCipherSpec " +
            "message at the appropriate point in the handshake.", securitySeverity = SeverityLevel.CRITICAL)
    public void omitCCS(WorkflowRunner runner) {
        Config c = this.getConfig();
        runner.replaceSupportedCiphersuites = true;
        runner.replaceSelectedCiphersuite = true;

        WorkflowTrace workflowTrace = runner.generateWorkflowTraceUntilSendingMessage(WorkflowTraceType.HANDSHAKE, ProtocolMessageType.CHANGE_CIPHER_SPEC);
        workflowTrace.addTlsActions(
                new SendAction(new FinishedMessage()),
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(workflowTrace, c).validateFinal(i -> {
            WorkflowTrace trace = i.getWorkflowTrace();
            assertTrue(AssertMsgs.WorkflowNotExecuted, trace.executedAsPlanned());

            Validator.receivedFatalAlert(i);
        });
    }

}
