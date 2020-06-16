package de.rub.nds.tlstest.suite.tests.client.tls13.rfc8446;

import de.rub.nds.modifiablevariable.VariableModification;
import de.rub.nds.modifiablevariable.bytearray.ByteArrayDeleteModification;
import de.rub.nds.modifiablevariable.bytearray.ByteArrayModificationFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.*;
import de.rub.nds.tlstest.framework.constants.AssertMsgs;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.constants.TestStatus;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;

import java.util.Arrays;

import static org.junit.Assert.*;

@RFC(number = 8446, section = "4.1.3 Server Hello")
@ClientTest
public class ServerHello extends Tls13Test {

    @TlsTest(description = "A client which receives a legacy_session_id_echo " +
            "field that does not match what it sent in the ClientHello MUST " +
            "abort the handshake with an \"illegal_parameter\" alert.", interoperabilitySeverity = SeverityLevel.MEDIUM)
    public void testSessionId(WorkflowRunner runner) {
        Config c = this.getConfig();
        runner.replaceSelectedCiphersuite = true;

        ServerHelloMessage serverHello = new ServerHelloMessage(c);
        serverHello.setSessionId(Modifiable.explicit(new byte[]{0x01, 0x02, 0x03, 0x04}));

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                new ReceiveAction(new ClientHelloMessage(c)),
                new SendAction(serverHello),
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(workflowTrace, c).validateFinal(i -> {
            WorkflowTrace trace = i.getWorkflowTrace();
            Validator.receivedFatalAlert(i);

            AlertMessage msg = trace.getFirstReceivedMessage(AlertMessage.class);
            if (msg == null) {
                i.setStatus(TestStatus.PARTIALLY_FAILED);
                return;
            }

            assertNotNull(AssertMsgs.AlertNotReceived, msg);
            assertSame(AssertMsgs.UnexpectedAlertDescription, AlertDescription.ILLEGAL_PARAMETER, AlertDescription.getAlertDescription(msg.getDescription().getValue()));
        });
    }

    @TlsTest(description = "A client which receives a cipher suite that was " +
            "not offered MUST abort the handshake with " +
            "an \"illegal_parameter\" alert.", interoperabilitySeverity = SeverityLevel.MEDIUM)
    public void testCipherSuite(WorkflowRunner runner) {
        Config c = this.getConfig();
        runner.replaceSelectedCiphersuite = true;

        ServerHelloMessage serverHello = new ServerHelloMessage(c);
        serverHello.setSelectedCipherSuite(Modifiable.explicit(CipherSuite.GREASE_00.getByteValue()));

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                new ReceiveAction(new ClientHelloMessage(c)),
                new SendAction(serverHello),
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(workflowTrace, c).validateFinal(i -> {
            WorkflowTrace trace = i.getWorkflowTrace();
            Validator.receivedFatalAlert(i);

            AlertMessage msg = trace.getFirstReceivedMessage(AlertMessage.class);
            if (msg == null) {
                i.setStatus(TestStatus.PARTIALLY_FAILED);
                return;
            }

            assertNotNull(AssertMsgs.AlertNotReceived, msg);
            assertSame(AssertMsgs.UnexpectedAlertDescription, AlertDescription.ILLEGAL_PARAMETER, AlertDescription.getAlertDescription(msg.getDescription().getValue()));
        });
    }


    @TlsTest(description = "legacy_compression_method: A single byte which " +
            "MUST have the value 0.", interoperabilitySeverity = SeverityLevel.MEDIUM)
    public void testCompressionValue(WorkflowRunner runner) {
        Config c = this.getConfig();
        runner.replaceSelectedCiphersuite = true;

        ServerHelloMessage serverHello = new ServerHelloMessage(c);
        serverHello.setSelectedCompressionMethod(Modifiable.explicit((byte) 0x01));

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                new ReceiveAction(new ClientHelloMessage(c)),
                new SendAction(serverHello),
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(workflowTrace, c).validateFinal(i -> {
            WorkflowTrace trace = i.getWorkflowTrace();
            Validator.receivedFatalAlert(i);

            AlertMessage msg = trace.getFirstReceivedMessage(AlertMessage.class);
            if (msg == null) {
                i.setStatus(TestStatus.PARTIALLY_FAILED);
                return;
            }
            assertNotNull(AssertMsgs.AlertNotReceived, msg);
        });
    }


    @TlsTest(description = "TLS 1.3 clients receiving a ServerHello indicating TLS 1.2 or below MUST " +
            "check that the last 8 bytes are not equal to either of these values. " +
            "If a match is found, the client MUST abort the handshake " +
            "with an \"illegal_parameter\" alert.", interoperabilitySeverity = SeverityLevel.MEDIUM)
    public void testRandomDowngradeValue(WorkflowRunner runner) {
        Config c = context.getConfig().createConfig();
        runner.replaceSelectedCiphersuite = true;

        ModifiableByteArray downgradeRandom = new ModifiableByteArray();
        VariableModification<byte[]> mod = ByteArrayModificationFactory.insert(new byte[]{0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01}, 24);
        mod.setPostModification(ByteArrayModificationFactory.delete(32, 8));
        downgradeRandom.setModification(mod);

        WorkflowTrace workflowTrace = runner.generateWorkflowTraceUntilSendingMessage(WorkflowTraceType.HANDSHAKE, HandshakeMessageType.SERVER_HELLO_DONE);
        workflowTrace.addTlsActions(
                new SendAction(new ServerHelloDoneMessage()),
                new ReceiveAction(new AlertMessage())
        );
        runner.setStateModifier(i -> {
            WorkflowTrace w = i.getWorkflowTrace();
            w.getFirstSendMessage(ServerHelloMessage.class).setRandom(downgradeRandom);
            return null;
        });

        runner.execute(workflowTrace, c).validateFinal(i -> {
            WorkflowTrace trace = i.getWorkflowTrace();
            Validator.receivedFatalAlert(i);

            AlertMessage msg = trace.getFirstReceivedMessage(AlertMessage.class);
            if (msg == null) {
                i.setStatus(TestStatus.PARTIALLY_FAILED);
                return;
            }
            assertSame(AssertMsgs.UnexpectedAlertDescription, AlertDescription.ILLEGAL_PARAMETER, AlertDescription.getAlertDescription(msg.getDescription().getValue()));
        });
    }

}
