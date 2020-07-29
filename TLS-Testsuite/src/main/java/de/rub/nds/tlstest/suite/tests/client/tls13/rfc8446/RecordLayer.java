package de.rub.nds.tlstest.suite.tests.client.tls13.rfc8446;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceMutator;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.ClientTest;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.ServerTest;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;

@ClientTest
@RFC(number = 8446, section = "5.1. Record Layer")
public class RecordLayer extends Tls13Test {


    @TlsTest(description = "Implementations MUST NOT send " +
            "zero-length fragments of Handshake types, even " +
            "if those fragments contain padding.", interoperabilitySeverity = SeverityLevel.MEDIUM)
    public void zeroLengthRecord_ServerHello(WorkflowRunner runner) {
        runner.replaceSelectedCiphersuite = true;

        Config c = this.getConfig();
        c.setUseAllProvidedRecords(true);

        Record record = new Record();
        record.setMaxRecordLengthConfig(0);

        WorkflowTrace trace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        trace.addTlsActions(
                new ReceiveAction(new AlertMessage())
        );

        runner.setStateModifier(i -> {
            WorkflowTrace t = i.getWorkflowTrace();
            WorkflowTraceMutator.deleteSendingMessage(t, HandshakeMessageType.SERVER_HELLO);
            SendAction serverHello = new SendAction(new ServerHelloMessage(c));
            serverHello.setRecords(record);
            t.addTlsAction(1, serverHello);
            return null;
        });

        runner.execute(trace, c).validateFinal(Validator::receivedFatalAlert);
    }

    @TlsTest(description = "Implementations MUST NOT send " +
            "zero-length fragments of Handshake types, even " +
            "if those fragments contain padding.", interoperabilitySeverity = SeverityLevel.MEDIUM)
    public void zeroLengthRecord_Finished(WorkflowRunner runner) {
        runner.replaceSelectedCiphersuite = true;

        Config c = this.getConfig();
        c.setUseAllProvidedRecords(true);

        Record record = new Record();
        record.setMaxRecordLengthConfig(0);

        WorkflowTrace trace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        trace.addTlsActions(
                new ReceiveAction(new AlertMessage())
        );

        runner.setStateModifier(i -> {
            WorkflowTrace t = i.getWorkflowTrace();
            WorkflowTraceMutator.deleteSendingMessage(t, HandshakeMessageType.FINISHED);
            SendAction finished = new SendAction(new FinishedMessage(c));
            finished.setRecords(record);
            t.addTlsAction(2, finished);
            return null;
        });

        runner.execute(trace, c).validateFinal(Validator::receivedFatalAlert);
    }

    @TlsTest(description = "Handshake messages MUST NOT be interleaved " +
            "with other record types.", interoperabilitySeverity = SeverityLevel.CRITICAL, securitySeverity = SeverityLevel.MEDIUM)
    public void interleaveRecords(WorkflowRunner runner) {
        runner.replaceSelectedCiphersuite = true;

        Config c = this.getConfig();
        c.setCreateIndividualRecords(false);
        c.setFlushOnMessageTypeChange(false);

        WorkflowTrace trace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        trace.addTlsAction(new ReceiveAction(new AlertMessage()));

        runner.execute(trace, c).validateFinal(Validator::receivedFatalAlert);
    }
}
