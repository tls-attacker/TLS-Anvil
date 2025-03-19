/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.both.tls13.statemachine;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.teststate.AnvilTestCase;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
import java.util.List;

/** Statemachine tests used both for TLS 1.3 clients and servers. */
public class ClientServerStateMachine extends Tls13Test {

    @AnvilTest(id = "XSM-tGmYudnsgE")
    public void sendEmptyRecordFinished(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);

        Record r = new Record();
        r.setContentMessageType(ProtocolMessageType.APPLICATION_DATA);
        r.setProtocolMessageBytes(Modifiable.explicit(new byte[0]));
        r.setMaxRecordLengthConfig(0);
        SendAction fin = new SendAction(new FinishedMessage());
        fin.setConfiguredRecords(List.of(r));

        WorkflowTrace workflowTrace =
                runner.generateWorkflowTraceUntilSendingMessage(
                        WorkflowTraceType.HANDSHAKE, HandshakeMessageType.FINISHED);
        workflowTrace.addTlsActions(fin, new ReceiveAction(new AlertMessage()));

        State state = runner.execute(workflowTrace, c);
        Validator.receivedFatalAlert(state, testCase);
    }
}
