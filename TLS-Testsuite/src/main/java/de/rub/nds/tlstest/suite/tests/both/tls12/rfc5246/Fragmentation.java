package de.rub.nds.tlstest.suite.tests.both.tls12.rfc5246;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.constants.AssertMsgs;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;

import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

@RFC(number = 5264, section = "6.2.1 Fragmentation")
public class Fragmentation extends Tls12Test {

    @TlsTest(description = "Implementations MUST NOT send zero-length fragments of Handshake, " +
            "Alert, or ChangeCipherSpec content types. Zero-length fragments of " +
            "Application data MAY be sent as they are potentially useful as a " +
            "traffic analysis countermeasure.")
    @KeyExchange(supported = KeyExchangeType.ALL12)
    public void sendZeroLengthRecord_CCS(WorkflowRunner runner) {
        Config c = this.getConfig();
        c.setDefaultClientSupportedCiphersuites(CipherSuite.getImplemented());
        c.setUseAllProvidedRecords(true);
        runner.replaceSupportedCiphersuites = true;

        Record r = new Record();
        r.setContentMessageType(ProtocolMessageType.CHANGE_CIPHER_SPEC);
        r.setMaxRecordLengthConfig(0);
        SendAction sendAction = new SendAction(new ChangeCipherSpecMessage(c));
        sendAction.setRecords(r);

        WorkflowTrace workflowTrace = runner.generateWorkflowTraceUntilSendingMessage(WorkflowTraceType.HANDSHAKE, ProtocolMessageType.CHANGE_CIPHER_SPEC);
        workflowTrace.addTlsActions(
                sendAction,
                new SendAction(new FinishedMessage()),
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(workflowTrace, c).validateFinal(Validator::receivedFatalAlert);
    }


    @TlsTest(description = "Implementations MUST NOT send zero-length fragments of Handshake, " +
            "Alert, or ChangeCipherSpec content types. Zero-length fragments of " +
            "Application data MAY be sent as they are potentially useful as a " +
            "traffic analysis countermeasure.")
    @KeyExchange(supported = KeyExchangeType.ALL12)
    public void sendZeroLengthApplicationRecord(WorkflowRunner runner) {
        Config c = this.getConfig();
        runner.replaceSupportedCiphersuites = true;

        ApplicationMessage appMsg = new ApplicationMessage(c);
        appMsg.setData(Modifiable.explicit(new byte[3]));

        Record r = new Record();
        r.setContentMessageType(ProtocolMessageType.APPLICATION_DATA);
        r.setMaxRecordLengthConfig(0);
        SendAction sendAction = new SendAction(appMsg);
        sendAction.setRecords(r);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        workflowTrace.addTlsActions(
                sendAction,
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(workflowTrace, c).validateFinal(i -> {
            WorkflowTrace trace = i.getWorkflowTrace();
            assertTrue(AssertMsgs.WorkflowNotExecuted, trace.smartExecutedAsPlanned());

            AlertMessage msg = trace.getFirstReceivedMessage(AlertMessage.class);
            assertNull("Received alert message", msg);
        });

    }

    @TlsTest(description = "The length (in bytes) of the following TLSPlaintext.fragment. The\n" +
            "length MUST NOT exceed 2^14.")
    @KeyExchange(supported = KeyExchangeType.ALL12)
    public void sendRecordWithLengthOver2pow14plus1(WorkflowRunner runner) {
        Config c = this.getConfig();
        runner.replaceSupportedCiphersuites = true;

        ApplicationMessage msg = new ApplicationMessage(c);
        msg.setData(Modifiable.explicit(new byte[(int) (Math.pow(2, 14)) + 1]));

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        workflowTrace.addTlsActions(
                new SendAction(msg),
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(workflowTrace, c).validateFinal(i -> {
            WorkflowTrace trace = i.getWorkflowTrace();
            assertTrue(AssertMsgs.WorkflowNotExecuted, trace.executedAsPlanned());

            Validator.receivedFatalAlert(i);
        });
    }
}
