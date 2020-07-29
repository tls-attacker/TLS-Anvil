package de.rub.nds.tlstest.suite.tests.server.tls12.rfc5246;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.*;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;

@ServerTest
@RFC(number = 5246, section = "7.4.8. Certificate Verify")
public class CertificateVerify extends Tls12Test {
    public ConditionEvaluationResult clientAuth() {
        if (this.getConfig().isClientAuthentication()) {
            return ConditionEvaluationResult.enabled("");
        }
        return ConditionEvaluationResult.disabled("No client auth required");
    }

    @TlsTest(description = "Here handshake_messages refers to all handshake messages sent or received, " +
            "starting at client hello and up to, but not including, this message, including the " +
            "type and length fields of the handshake messages. This is the concatenation of all " +
            "the Handshake structures (as defined in Section 7.4) exchanged thus far.", securitySeverity = SeverityLevel.CRITICAL)
    @MethodCondition(method = "clientAuth")
    public void invalidCertificateVerify(WorkflowRunner runner) {
        Config c = this.getConfig();
        runner.replaceSupportedCiphersuites = true;

        WorkflowTrace workflowTrace = runner.generateWorkflowTraceUntilSendingMessage(WorkflowTraceType.HANDSHAKE, HandshakeMessageType.FINISHED);
        workflowTrace.addTlsActions(
                new SendAction(true, new FinishedMessage()),
                new ReceiveAction(new AlertMessage())
        );

        runner.setStateModifier(i -> {
            CertificateVerifyMessage msg = i.getWorkflowTrace().getFirstSendMessage(CertificateVerifyMessage.class);
            msg.setSignature(Modifiable.xor(new byte[]{0x01}, 0));
            return null;
        });

        runner.execute(workflowTrace, c).validateFinal(Validator::receivedFatalAlert);
    }

}
