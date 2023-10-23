package de.rub.nds.tlstest.suite.tests.both.dtls12.rfc6347;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
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
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@RFC(number = 6347, section = "4.1.2.1. MAC")
@Tag("dtls12")
public class MAC extends Dtls12Test {

    @Tag("Test2")
    @TlsTest(
            description =
                    "If a DTLS implementation chooses to generate an alert when it receives a message with an invalid MAC, it MUST generate a bad_record_mac alert with level fatal and terminate its connection state.")
    @ScopeExtensions(DerivationType.MAC_BITMASK)
    /**
     * This test checks that the alert description for an invalid MAC is "BAD_RECORD_MAC". So far
     * the Finished message is used for the test. Since this still belongs to the handshake, a
     * "DECRYPT_ERROR" is also possible.
     *
     * <p>TODO to optimize the test this could be split in a verification of the error message in
     * the handshake and a test based on application data.
     */
    public void badMACAlert(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
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
                            WorkflowTrace executedTrace = i.getWorkflowTrace();

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

                            AlertMessage msg =
                                    executedTrace.getFirstReceivedMessage(AlertMessage.class);
                            Validator.testAlertDescription(i, AlertDescription.DECRYPT_ERROR, msg);
                            // Validator.testAlertDescription(i, AlertDescription.BAD_RECORD_MAC,
                            // msg);
                        });
    }
}