package de.rub.nds.tlstest.suite.tests.server.dtls12.rfc6347;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Dtls12Test;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@Tag("dtls12")
public class RecordLayer extends Dtls12Test {

    /**
     * This test tests the behavior when the wrong epoch is used in a finished message and it is
     * reduced. The test is successful if such a message is ignored or rejected with a FatalAlert.
     */
    @Tag("Test1")
    @AnvilTest(id = "6347-Krh31b84Lx")
    public void decreaseEpoche(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        Record recordKeyExchange = new Record();
        recordKeyExchange.setContentMessageType(ProtocolMessageType.HANDSHAKE);
        Record recordCipherSpec = new Record();
        recordCipherSpec.setContentMessageType(ProtocolMessageType.HANDSHAKE);
        Record recordFinished = new Record();
        recordFinished.setContentMessageType(ProtocolMessageType.HANDSHAKE);
        recordFinished.setEpoch(Modifiable.sub(1));

        WorkflowTrace workflowTrace =
                runner.generateWorkflowTraceUntilSendingMessage(
                        WorkflowTraceType.HANDSHAKE, ProtocolMessageType.CHANGE_CIPHER_SPEC);

        SendAction temp = (SendAction) workflowTrace.getLastSendingAction();
        temp.getMessages().add(new ChangeCipherSpecMessage());
        temp.getMessages().add(new FinishedMessage());

        temp.getRecords().add(recordKeyExchange);
        temp.getRecords().add(recordCipherSpec);
        temp.getRecords().add(recordFinished);
        workflowTrace.addTlsActions(new ReceiveAction(new AlertMessage()));

        runner.execute(workflowTrace, c)
                .validateFinal(
                        i -> {
                            Validator.receivedFatalAlert(i);
                        });
    }
}
