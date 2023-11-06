/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.client.tls12.rfc6066;

import static org.junit.Assert.assertTrue;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.ClientTest;
import de.rub.nds.anvilcore.annotation.ExcludeParameter;
import de.rub.nds.anvilcore.annotation.MethodCondition;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.MaxFragmentLength;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.MaxFragmentLengthExtensionMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceivingAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@ClientTest
public class MaximumFragmentLength extends Tls12Test {

    public ConditionEvaluationResult sentMaximumFragmentLength() {
        if (context.getReceivedClientHelloMessage()
                .containsExtension(ExtensionType.MAX_FRAGMENT_LENGTH)) {
            return ConditionEvaluationResult.enabled("");
        }
        return ConditionEvaluationResult.disabled(
                "Client does not support maximum fragment length");
    }

    private MaxFragmentLength getUnrequestedMaxFragLen(MaxFragmentLengthExtensionMessage req) {
        for (MaxFragmentLength len : MaxFragmentLength.values()) {
            if (req.getMaxFragmentLength().getValue()[0] != len.getValue()) {
                return len;
            }
        }
        return MaxFragmentLength.TWO_11;
    }

    @AnvilTest(id = "6066-WpGEGtHscM")
    @MethodCondition(method = "sentMaximumFragmentLength")
    @ExcludeParameter("RECORD_LENGTH")
    public void invalidMaximumFragmentLength(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        c.setAddMaxFragmentLengthExtension(true);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsActions(new ReceiveAction(new AlertMessage()));

        ServerHelloMessage serverHello =
                workflowTrace.getFirstSendMessage(ServerHelloMessage.class);
        serverHello
                .getExtension(MaxFragmentLengthExtensionMessage.class)
                .setMaxFragmentLength(Modifiable.explicit(new byte[] {5}));

        runner.execute(workflowTrace, c)
                .validateFinal(
                        i -> {
                            Validator.receivedFatalAlert(i);

                            WorkflowTrace trace = i.getWorkflowTrace();
                            AlertMessage alert = trace.getLastReceivedMessage(AlertMessage.class);
                            Validator.testAlertDescription(
                                    i, AlertDescription.ILLEGAL_PARAMETER, alert);
                        });
    }

    @AnvilTest(id = "6066-ossqki78mA")
    @MethodCondition(method = "sentMaximumFragmentLength")
    @ExcludeParameter("RECORD_LENGTH")
    public void unrequestedMaximumFragmentLength(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        c.setAddMaxFragmentLengthExtension(true);

        MaxFragmentLength unreqLen =
                getUnrequestedMaxFragLen(
                        context.getReceivedClientHelloMessage()
                                .getExtension(MaxFragmentLengthExtensionMessage.class));

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsActions(new ReceiveAction(new AlertMessage()));

        ServerHelloMessage serverHello =
                workflowTrace.getFirstSendMessage(ServerHelloMessage.class);
        serverHello
                .getExtension(MaxFragmentLengthExtensionMessage.class)
                .setMaxFragmentLength(Modifiable.explicit(new byte[] {unreqLen.getValue()}));

        runner.execute(workflowTrace, c)
                .validateFinal(
                        i -> {
                            Validator.receivedFatalAlert(i);

                            WorkflowTrace trace = i.getWorkflowTrace();
                            AlertMessage alert = trace.getLastReceivedMessage(AlertMessage.class);
                            Validator.testAlertDescription(
                                    i, AlertDescription.ILLEGAL_PARAMETER, alert);
                        });
    }

    @AnvilTest(id = "6066-XXJU5VtxbB")
    @MethodCondition(method = "sentMaximumFragmentLength")
    @Tag("new")
    public void respectsNegotiatedMaxFragmentLength(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        c.setAddMaxFragmentLengthExtension(true);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);

        runner.execute(workflowTrace, c)
                .validateFinal(
                        i -> {
                            Validator.executedAsPlanned(i);
                            ClientHelloMessage clientHello =
                                    i.getWorkflowTrace()
                                            .getFirstSendMessage(ClientHelloMessage.class);
                            MaxFragmentLength selectedMaxFragment =
                                    MaxFragmentLength.getMaxFragmentLength(
                                            clientHello
                                                    .getExtension(
                                                            MaxFragmentLengthExtensionMessage.class)
                                                    .getMaxFragmentLength()
                                                    .getValue()[0]);
                            int maxPlaintextFragmentSize =
                                    MaxFragmentLength.getIntegerRepresentation(selectedMaxFragment);

                            WorkflowTrace trace = i.getWorkflowTrace();
                            for (int j = 1; j < trace.getReceivingActions().size(); j++) {
                                ReceivingAction receiveAction = trace.getReceivingActions().get(j);
                                if (receiveAction.getReceivedRecords() != null) {
                                    for (Record receivedRecord :
                                            receiveAction.getReceivedRecords()) {
                                        assertTrue(
                                                "Plaintextbytes of record exceeded limit",
                                                ((Record) receivedRecord)
                                                                .getCleanProtocolMessageBytes()
                                                                .getValue()
                                                                .length
                                                        <= maxPlaintextFragmentSize);
                                    }
                                }
                            }
                        });
    }
}
