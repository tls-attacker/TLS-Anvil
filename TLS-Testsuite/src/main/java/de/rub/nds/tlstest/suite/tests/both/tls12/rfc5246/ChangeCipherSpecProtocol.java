package de.rub.nds.tlstest.suite.tests.both.tls12.rfc5246;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;

import static org.junit.Assert.assertEquals;


@RFC(number = 5264, section = "7.1 Change Cipher Spec Protocol")
public class ChangeCipherSpecProtocol extends Tls12Test {

    private void ccsContentTest(WorkflowRunner runner, byte[] content) {
        Config c = this.getConfig();
        runner.replaceSupportedCiphersuites = true;
        runner.replaceSelectedCiphersuite = true;

        ChangeCipherSpecMessage changeCipherSpecMessage = new ChangeCipherSpecMessage(c);
        changeCipherSpecMessage.setCcsProtocolType(Modifiable.explicit(content));

        WorkflowTrace workflowTrace = runner.generateWorkflowTraceUntilSendingMessage(WorkflowTraceType.HANDSHAKE, ProtocolMessageType.CHANGE_CIPHER_SPEC);
        workflowTrace.addTlsActions(
                new SendAction(changeCipherSpecMessage),
                new SendAction(true, new FinishedMessage()),
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(workflowTrace, c).validateFinal(i -> {
            WorkflowTrace trace = i.getWorkflowTrace();
            Validator.receivedFatalAlert(i);

            ChangeCipherSpecMessage msg = trace.getFirstReceivedMessage(ChangeCipherSpecMessage.class);
            if (msg != null) {
                assertEquals(1, msg.getCcsProtocolType().getValue().length);
                assertEquals(1, msg.getCcsProtocolType().getValue()[0]);
            }
        });
    }

    @TlsTest(description = "The message consists of a single byte of value 1.", interoperabilitySeverity = SeverityLevel.CRITICAL)
    public void contentOfCCS(WorkflowRunner runner) {
        ccsContentTest(runner, new byte[]{(byte)125});
    }

    @TlsTest(description = "The message consists of a single byte of value 1.", interoperabilitySeverity = SeverityLevel.CRITICAL)
    public void contentOfCCSMoreThanOneByte(WorkflowRunner runner) {
        ccsContentTest(runner, new byte[]{(byte)1, 1});
    }
}
