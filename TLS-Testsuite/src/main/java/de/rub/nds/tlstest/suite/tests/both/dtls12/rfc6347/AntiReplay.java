package de.rub.nds.tlstest.suite.tests.both.dtls12.rfc6347;

import static org.junit.Assert.assertTrue;
import static org.junit.jupiter.api.Assertions.assertFalse;

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
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.ScopeExtensions;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.constants.TestEndpointType;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.DerivationType;
import de.rub.nds.tlstest.framework.testClasses.Dtls12Test;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@RFC(number = 6347, section = "4.1.2.6. Anti-Replay")
@Tag("dtls12")
public class AntiReplay extends Dtls12Test {

    @Tag("Test4")
    @TlsTest(
            description =
                    "The receiver packet counter for this session MUST be initialized to"
                            + "   zero when the session is established.")
    /**
     * This test checks if the sequenceNumber in the first record from the Client and the first
     * record from the server is 0.
     */
    public void packetStartWithZero(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace trace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);

        runner.execute(trace, c)
                .validateFinal(
                        i -> {
                            assertTrue(
                                    trace.getFirstReceivingAction()
                                                    .getReceivedRecords()
                                                    .get(0)
                                                    .getSequenceNumber()
                                                    .getValue()
                                                    .intValue()
                                            == 0);
                        });
    }

    @Tag("Test5")
    @TlsTest(
            description =
                    "For each received record, the receiver MUST verify that the record contains a sequence number that does not duplicate the sequence number of any other record received during the life of this session.")
    /**
     * This test checks that no SeqeunceNumber occurs twice. All values used in the handshake are
     * converted into one value to compare it with the others. If this value does not occur in a
     * list with all sequenceNumbers sent so far in the test, the value is added to the list.
     *
     * <p>The test is passed if each value occurs only once and no value was used twice.
     */
    public void sequenceNumberNotDuplicated(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        List<Integer> values = new ArrayList<>();

        Config c = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace trace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);

        runner.execute(trace, c)
                .validateFinal(
                        i -> {
                            for (ReceivingAction action :
                                    i.getWorkflowTrace().getReceivingActions()) {
                                if (action.getReceivedRecords() != null) {
                                    for (Record record : action.getReceivedRecords()) {
                                        assertFalse(
                                                values.contains(
                                                        record.getEpoch().getValue() * 10000000
                                                                + record.getSequenceNumber()
                                                                        .getValue()
                                                                        .intValue()),
                                                action.toString());
                                        values.add(
                                                record.getEpoch().getValue() * 10000000
                                                        + record.getSequenceNumber()
                                                                .getValue()
                                                                .intValue());
                                    }
                                }
                            }
                        });
    }

    @Tag("Test3")
    @TlsTest(
            description =
                    "If the MAC validation fails, the receiver MUST"
                            + "   discard the received record as invalid.")
    @ScopeExtensions(DerivationType.MAC_BITMASK)
    /**
     * In this test, the behavior with an invalid MAC is tested. A message is sent with an invalid
     * MAC. This must be ignored by the communication partner.
     */
    public void invalidMAC(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        byte[] bitmask = derivationContainer.buildBitmask();

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
                            // When adding an AlertMessage at the client, an additional
                            // ApplicationMessage is automatically added to the workflow. Since this
                            // is not sent by the client in any case, this message must be removed
                            // to perform the test successfully.
                            if (getTestContext().getConfig().getTestEndpointMode()
                                            == TestEndpointType.CLIENT
                                    && ((ReceiveAction)
                                                            i.getWorkflowTrace()
                                                                    .getLastReceivingAction())
                                                    .getExpectedMessages()
                                                    .size()
                                            > 1) {
                                ((ReceiveAction) i.getWorkflowTrace().getLastReceivingAction())
                                        .getExpectedMessages()
                                        .remove(0);
                            }
                            Validator.receivedFatalAlert(i);
                        });
    }
}