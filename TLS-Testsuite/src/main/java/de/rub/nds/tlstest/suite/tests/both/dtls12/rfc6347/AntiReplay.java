package de.rub.nds.tlstest.suite.tests.both.dtls12.rfc6347;

import static org.junit.jupiter.api.Assertions.fail;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.IncludeParameter;
import de.rub.nds.anvilcore.annotation.MethodCondition;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceivingAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Dtls12Test;
import de.rub.nds.tlstest.suite.util.DtlsTestConditions;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

public class AntiReplay extends Dtls12Test {

    @AnvilTest(id = "6347-GeZa64E0Nt")
    /**
     * This test checks that no SeqeunceNumber occurs twice. All values used in the handshake are
     * converted into one value to compare it with the others. If this value does not occur in a
     * list with all sequenceNumbers sent so far in the test, the value is added to the list.
     *
     * <p>The test is passed if each value occurs only once and no value was used twice.
     */
    public void sequenceNumberNotDuplicated(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace trace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);

        runner.execute(trace, c)
                .validateFinal(
                        i -> {
                            Map<Integer, List<Long>> epochSqnMap = new HashMap<>();
                            for (ReceivingAction action :
                                    i.getWorkflowTrace().getReceivingActions()) {
                                if (action.getReceivedRecords() != null) {
                                    for (Record record : action.getReceivedRecords()) {
                                        if (epochSqnMap
                                                .computeIfAbsent(
                                                        record.getEpoch().getValue(),
                                                        (epoch) -> {
                                                            return new LinkedList<>();
                                                        })
                                                .contains(
                                                        record.getSequenceNumber()
                                                                .getValue()
                                                                .longValue())) {
                                            fail(
                                                    "Peer sent pair epoch "
                                                            + record.getEpoch().getValue()
                                                            + " and sequence number "
                                                            + record.getSequenceNumber()
                                                                    .getValue()
                                                                    .longValue()
                                                            + " twice.");
                                        }
                                        epochSqnMap
                                                .get(record.getEpoch().getValue())
                                                .add(
                                                        record.getSequenceNumber()
                                                                .getValue()
                                                                .longValue());
                                    }
                                }
                            }
                        });
    }

    @AnvilTest(id = "6347-rMf9lpA6G3")
    @IncludeParameter("MAC_BITMASK")
    @MethodCondition(clazz = DtlsTestConditions.class, method = "isServerTestOrClientSendsAppData")
    /**
     * In this test, the behavior with an invalid MAC is tested. A message is sent with an invalid
     * MAC. This must be ignored by the communication partner.
     */
    public void invalidMAC(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        byte[] bitmask = parameterCombination.buildBitmask();

        FinishedMessage finishedMessage = new FinishedMessage();
        finishedMessage.setVerifyData(Modifiable.xor(bitmask, 0));

        SendAction sendAction = new SendAction(finishedMessage);

        WorkflowTrace trace =
                runner.generateWorkflowTraceUntilSendingMessage(
                        WorkflowTraceType.HANDSHAKE, HandshakeMessageType.FINISHED);

        trace.addTlsActions(sendAction, new ReceiveAction(new AlertMessage()));

        runner.execute(trace, c)
                .validateFinal(
                        i -> {
                            Validator.receivedFatalAlert(i);
                        });
    }
}
