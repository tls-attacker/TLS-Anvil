/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.server.tls12.rfc5246;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.ExcludeParameter;
import de.rub.nds.anvilcore.annotation.ExcludeParameters;
import de.rub.nds.anvilcore.annotation.ServerTest;
import de.rub.nds.anvilcore.teststate.AnvilTestCase;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendDynamicClientKeyExchangeAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsattacker.transport.TransportHandlerType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.EnforcedSenderRestriction;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import java.util.List;

@ServerTest
public class Fragmentation extends Tls12Test {

    @AnvilTest(id = "5246-J6zSpKaaXP")
    @ExcludeParameter("RECORD_LENGTH")
    @EnforcedSenderRestriction
    public void sendZeroLengthRecord_CH(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);
        c.setUseAllProvidedRecords(true);

        Record r = new Record();
        r.setContentMessageType(ProtocolMessageType.HANDSHAKE);
        r.setMaxRecordLengthConfig(0);
        ClientHelloMessage cHello = new ClientHelloMessage(c);
        cHello.setProtocolVersion(ProtocolVersion.TLS12.getValue());
        SendAction sendAction = new SendAction(cHello);
        sendAction.setConfiguredRecords(List.of(r));

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(sendAction, new ReceiveAction(new AlertMessage()));

        State state = runner.execute(workflowTrace, c);
        Validator.receivedFatalAlert(state, testCase);
        ;
    }

    @AnvilTest(id = "5246-2FWjWfzv3Q")
    @ExcludeParameter("RECORD_LENGTH")
    @EnforcedSenderRestriction
    public void sendZeroLengthRecord_Alert(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);
        c.setUseAllProvidedRecords(true);

        AlertMessage alertMsg = new AlertMessage();
        alertMsg.setLevel(Modifiable.explicit(AlertLevel.WARNING.getValue()));
        alertMsg.setDescription(Modifiable.explicit(AlertDescription.CLOSE_NOTIFY.getValue()));

        Record r = new Record();
        r.setContentMessageType(ProtocolMessageType.ALERT);
        r.setMaxRecordLengthConfig(0);
        SendAction sendAction = new SendAction(alertMsg);
        sendAction.setConfiguredRecords(List.of(r));

        WorkflowTrace workflowTrace =
                runner.generateWorkflowTraceUntilSendingMessage(
                        WorkflowTraceType.HELLO, HandshakeMessageType.CLIENT_KEY_EXCHANGE);
        workflowTrace.addTlsActions(sendAction, new ReceiveAction(new AlertMessage()));

        State state = runner.execute(workflowTrace, c);
        Validator.receivedFatalAlert(state, testCase);
        ;
    }

    // TODO Must be excluded from DTLS test, because of the TCP_FRAGMENTATION.
    @AnvilTest(id = "5246-yNEWNcjFZF")
    @ExcludeParameters({@ExcludeParameter("RECORD_LENGTH"), @ExcludeParameter("TCP_FRAGMENTATION")})
    public void sendHandshakeMessagesWithinMultipleRecords_CKE_CCS_F(
            AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        if (c.isClientAuthentication()) {
            workflowTrace.addTlsActions(new SendAction(new CertificateMessage()));
        }
        workflowTrace.addTlsActions(new SendDynamicClientKeyExchangeAction());

        if (c.isClientAuthentication()) {
            workflowTrace.addTlsActions(new SendAction(new CertificateVerifyMessage()));
        }

        workflowTrace.addTlsActions(new SendAction(new ChangeCipherSpecMessage()));
        workflowTrace.addTlsActions(new SendAction(new FinishedMessage()));
        workflowTrace.addTlsActions(
                new ReceiveAction(new ChangeCipherSpecMessage(), new FinishedMessage()));

        State state = runner.execute(workflowTrace, c);
        Validator.executedAsPlanned(state, testCase);
    }

    // TODO Must be excluded from DTLS test, because of the TCP_FRAGMENTATION.
    @AnvilTest(id = "5246-RNQeBZXVNc")
    @ExcludeParameters({@ExcludeParameter("RECORD_LENGTH"), @ExcludeParameter("TCP_FRAGMENTATION")})
    public void sendHandshakeMessagesWithinMultipleRecords_CKE_CCSF(
            AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);
        c.getDefaultClientConnection().setTransportHandlerType(TransportHandlerType.TCP_NO_DELAY);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        if (c.isClientAuthentication()) {
            workflowTrace.addTlsActions(new SendAction(new CertificateMessage()));
        }
        workflowTrace.addTlsActions(new SendDynamicClientKeyExchangeAction());

        if (c.isClientAuthentication()) {
            workflowTrace.addTlsActions(new SendAction(new CertificateVerifyMessage()));
        }

        workflowTrace.addTlsActions(
                new SendAction(new ChangeCipherSpecMessage(), new FinishedMessage()));
        workflowTrace.addTlsActions(
                new ReceiveAction(new ChangeCipherSpecMessage(), new FinishedMessage()));

        State state = runner.execute(workflowTrace, c);
        Validator.executedAsPlanned(state, testCase);
    }
}
