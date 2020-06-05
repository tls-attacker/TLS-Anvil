package de.rub.nds.tlstest.suite.tests.server.tls12.rfc5246;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.ServerTest;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.constants.AssertMsgs;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import static org.junit.Assert.*;


@RFC(number = 5246, section = "6. The TLS Record Protocol")
@ServerTest
public class TLSRecordProtocol extends Tls12Test {

    @TlsTest(description = "Implementations MUST NOT send record types not defined in this document " +
            "unless negotiated by some extension. If a TLS implementation receives an unexpected " +
            "record type, it MUST send an unexpected_message alert.", interoperabilitySeverity = SeverityLevel.MEDIUM)
    @KeyExchange(supported = KeyExchangeType.ALL12)
    public void sendNotDefinedRecordTypesWithClientHello(WorkflowRunner runner) {
        Config c = context.getConfig().createConfig();
        runner.replaceSupportedCiphersuites = true;

        Record record = new Record();
        record.setContentType(Modifiable.explicit((byte) 0xFF));

        SendAction sendHelloWithWrongRecordContentType = new SendAction(new ClientHelloMessage(c));
        sendHelloWithWrongRecordContentType.setRecords(record);

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                sendHelloWithWrongRecordContentType,
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(workflowTrace).validateFinal(i -> {
            Validator.receivedFatalAlert(i);

            AlertMessage msg = i.getWorkflowTrace().getFirstReceivedMessage(AlertMessage.class);
            Validator.testAlertDescription(i, AlertDescription.UNEXPECTED_MESSAGE, msg);
        });
    }

    @TlsTest(description = "Implementations MUST NOT send record types not defined in this document " +
            "unless negotiated by some extension. If a TLS implementation receives an unexpected " +
            "record type, it MUST send an unexpected_message alert.", interoperabilitySeverity = SeverityLevel.MEDIUM)
    @KeyExchange(supported = KeyExchangeType.ALL12)
    public void sendNotDefinedRecordTypesWithCCSAndFinished(WorkflowRunner runner) {
        Config c = context.getConfig().createConfig();
        Record record = new Record();
        record.setContentType(Modifiable.explicit((byte) 0xFF));

        SendAction sendActionWithBadRecord = new SendAction(new ChangeCipherSpecMessage(), new FinishedMessage());
        sendActionWithBadRecord.setRecords(record);

        WorkflowTrace workflowTrace = runner.generateWorkflowTraceUntilSendingMessage(WorkflowTraceType.HANDSHAKE, ProtocolMessageType.CHANGE_CIPHER_SPEC);
        workflowTrace.addTlsActions(
                sendActionWithBadRecord,
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(workflowTrace, c).validateFinal(i -> {
            Validator.receivedFatalAlert(i);

            AlertMessage msg = i.getWorkflowTrace().getFirstReceivedMessage(AlertMessage.class);
            Validator.testAlertDescription(i, AlertDescription.UNEXPECTED_MESSAGE, msg);
        });
    }
}
