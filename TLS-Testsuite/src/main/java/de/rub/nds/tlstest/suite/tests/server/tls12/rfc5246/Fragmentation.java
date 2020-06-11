package de.rub.nds.tlstest.suite.tests.server.tls12.rfc5246;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendDynamicClientKeyExchangeAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsattacker.transport.TransportHandlerType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.ServerTest;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.constants.AssertMsgs;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;

import static org.junit.Assert.assertTrue;

@RFC(number = 5264, section = "6.2.1 Fragmentation")
@ServerTest
public class Fragmentation extends Tls12Test {

    @TlsTest(description = "Implementations MUST NOT send zero-length fragments of Handshake, " +
            "Alert, or ChangeCipherSpec content types. Zero-length fragments of " +
            "Application data MAY be sent as they are potentially useful as a " +
            "traffic analysis countermeasure.")
    public void sendZeroLengthRecord_CH(WorkflowRunner runner) {
        Config c = this.getConfig();
        c.setDefaultClientSupportedCiphersuites(CipherSuite.getImplemented());
        c.setUseAllProvidedRecords(true);
        runner.replaceSupportedCiphersuites = true;

        Record r = new Record();
        r.setContentMessageType(ProtocolMessageType.HANDSHAKE);
        r.setMaxRecordLengthConfig(0);
        SendAction sendAction = new SendAction(new ClientHelloMessage(c));
        sendAction.setRecords(r);

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                sendAction,
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(workflowTrace, c).validateFinal(Validator::receivedFatalAlert);
    }

    @TlsTest(description = "Implementations MUST NOT send zero-length fragments of Handshake, " +
            "Alert, or ChangeCipherSpec content types. Zero-length fragments of " +
            "Application data MAY be sent as they are potentially useful as a " +
            "traffic analysis countermeasure.")
    public void sendZeroLengthRecord_Alert(WorkflowRunner runner) {
        Config c = this.getConfig();
        c.setDefaultClientSupportedCiphersuites(CipherSuite.getImplemented());
        c.setUseAllProvidedRecords(true);
        runner.replaceSupportedCiphersuites = true;

        AlertMessage alertMsg = new AlertMessage(c);
        alertMsg.setLevel(Modifiable.explicit(AlertLevel.WARNING.getValue()));
        alertMsg.setDescription(Modifiable.explicit(AlertDescription.CLOSE_NOTIFY.getValue()));

        Record r = new Record();
        r.setContentMessageType(ProtocolMessageType.ALERT);
        r.setMaxRecordLengthConfig(0);
        SendAction sendAction = new SendAction(alertMsg);
        sendAction.setRecords(r);

        WorkflowTrace workflowTrace = runner.generateWorkflowTraceUntilSendingMessage(WorkflowTraceType.HELLO, HandshakeMessageType.CLIENT_KEY_EXCHANGE);
        workflowTrace.addTlsActions(
                sendAction,
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(workflowTrace, c).validateFinal(Validator::receivedFatalAlert);
    }




    @TlsTest(description = "")
    public void sendHandshakeMessagesWithinMultipleRecords_CKE_CCS_F(WorkflowRunner runner) {
        Config c = this.getConfig();
        c.getDefaultClientConnection().setTransportHandlerType(TransportHandlerType.TCP_NO_DELAY);
        runner.replaceSupportedCiphersuites = true;

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        if (c.isClientAuthentication()) {
            workflowTrace.addTlsActions(new SendAction(new CertificateMessage(c)));
        }
        workflowTrace.addTlsActions(new SendDynamicClientKeyExchangeAction());

        if (c.isClientAuthentication()) {
            workflowTrace.addTlsActions(new SendAction(new CertificateVerifyMessage(c)));
        }

        workflowTrace.addTlsActions(new SendAction(new ChangeCipherSpecMessage(c)));
        workflowTrace.addTlsActions(new SendAction(new FinishedMessage(c)));
        workflowTrace.addTlsActions(new ReceiveAction(new ChangeCipherSpecMessage(), new FinishedMessage()));

        runner.execute(workflowTrace, c).validateFinal(i -> {
            assertTrue(AssertMsgs.WorkflowNotExecuted, i.getWorkflowTrace().executedAsPlanned());
        });
    }

    @TlsTest(description = "")
    public void sendHandshakeMessagesWithinMultipleRecords_CKE_CCSF(WorkflowRunner runner) {
        Config c = this.getConfig();
        c.getDefaultClientConnection().setTransportHandlerType(TransportHandlerType.TCP_NO_DELAY);
        runner.replaceSupportedCiphersuites = true;

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        if (c.isClientAuthentication()) {
            workflowTrace.addTlsActions(new SendAction(new CertificateMessage(c)));
        }
        workflowTrace.addTlsActions(new SendDynamicClientKeyExchangeAction());

        if (c.isClientAuthentication()) {
            workflowTrace.addTlsActions(new SendAction(new CertificateVerifyMessage(c)));
        }

        workflowTrace.addTlsActions(new SendAction(new ChangeCipherSpecMessage(c), new FinishedMessage(c)));
        workflowTrace.addTlsActions(new ReceiveAction(new ChangeCipherSpecMessage(), new FinishedMessage()));

        runner.execute(workflowTrace, c).validateFinal(i -> {
            assertTrue(AssertMsgs.WorkflowNotExecuted, i.getWorkflowTrace().executedAsPlanned());
        });
    }



}
