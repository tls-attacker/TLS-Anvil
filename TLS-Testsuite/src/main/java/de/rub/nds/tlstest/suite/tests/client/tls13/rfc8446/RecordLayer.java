package de.rub.nds.tlstest.suite.tests.client.tls13.rfc8446;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.core.protocol.message.EncryptedExtensionsMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceMutator;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.ClientTest;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.AnnotatedStateContainer;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
import org.junit.jupiter.api.Tag;

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
            ((SendAction)t.getTlsActions().get(2)).setOptional(true);
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

    @TlsTest(description = "Send a record without any content.",
            securitySeverity = SeverityLevel.CRITICAL,
            interoperabilitySeverity = SeverityLevel.HIGH)
    @Tag("emptyRecord")
    public void sendEmptyZeroLengthRecords(WorkflowRunner runner) {
        Config c = this.getConfig();
        runner.replaceSelectedCiphersuite = true;

        Record r = new Record();
        r.setContentMessageType(ProtocolMessageType.HANDSHAKE);
        r.setProtocolMessageBytes(Modifiable.explicit(new byte[0]));
        r.setMaxRecordLengthConfig(0);

        AnnotatedStateContainer container = new AnnotatedStateContainer();
        WorkflowTrace trace = runner.generateWorkflowTraceUntilSendingMessage(WorkflowTraceType.HANDSHAKE, HandshakeMessageType.ENCRYPTED_EXTENSIONS);
        SendAction action = new SendAction(new EncryptedExtensionsMessage(c), new CertificateMessage(c), new CertificateVerifyMessage(c));
        action.setRecords(r);
        trace.addTlsActions(action, new ReceiveAction(new AlertMessage()));
        runner.setStateModifier(i -> {i.addAdditionalTestInfo("encyptedExtension"); return null;});
        container.addAll(runner.prepare(trace, c));

        trace = runner.generateWorkflowTraceUntilSendingMessage(WorkflowTraceType.HANDSHAKE, HandshakeMessageType.CERTIFICATE);
        action = new SendAction(new CertificateMessage(c), new CertificateVerifyMessage(c));
        action.setRecords(r);
        trace.addTlsActions(action, new ReceiveAction(new AlertMessage()));
        runner.setStateModifier(i -> {i.addAdditionalTestInfo("certificate"); return null;});
        container.addAll(runner.prepare(trace, c));

        trace = runner.generateWorkflowTraceUntilSendingMessage(WorkflowTraceType.HANDSHAKE, HandshakeMessageType.CERTIFICATE_VERIFY);
        action = new SendAction(new CertificateVerifyMessage(c));
        action.setRecords(r);
        trace.addTlsActions(action, new ReceiveAction(new AlertMessage()));
        runner.setStateModifier(i -> {i.addAdditionalTestInfo("certifiate_verify"); return null;});
        container.addAll(runner.prepare(trace, c));

        runner.execute(container).validateFinal(Validator::receivedFatalAlert);
    }
}
