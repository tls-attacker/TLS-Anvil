/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.client.tls12.rfc6066;

import static org.junit.Assert.assertTrue;

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
import de.rub.nds.tlstest.framework.annotations.ClientTest;
import de.rub.nds.tlstest.framework.annotations.MethodCondition;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.ScopeLimitations;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.annotations.categories.AlertCategory;
import de.rub.nds.tlstest.framework.annotations.categories.ComplianceCategory;
import de.rub.nds.tlstest.framework.annotations.categories.HandshakeCategory;
import de.rub.nds.tlstest.framework.annotations.categories.InteroperabilityCategory;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.TlsParameterType;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;
import de.rub.nds.anvilcore.annotation.AnvilTest;

@RFC(number = 6066, section = "4. Maximum Fragment Length Negotiation")
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

    @AnvilTest(
            description =
                    "Similarly, if a client receives a maximum fragment length negotiation "
                            + "response that differs from the length it requested, it MUST also abort the handshake with an \"illegal_parameter\" alert.")
    @MethodCondition(method = "sentMaximumFragmentLength")
    @ScopeLimitations(TlsParameterType.RECORD_LENGTH)
    @HandshakeCategory(SeverityLevel.LOW)
    @AlertCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.MEDIUM)
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

    @AnvilTest(
            description =
                    "Similarly, if a client receives a maximum fragment length negotiation "
                            + "response that differs from the length it requested, it MUST also abort the handshake with an \"illegal_parameter\" alert.")
    @MethodCondition(method = "sentMaximumFragmentLength")
    @ScopeLimitations(TlsParameterType.RECORD_LENGTH)
    @HandshakeCategory(SeverityLevel.LOW)
    @AlertCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.MEDIUM)
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

    @AnvilTest(
            description =
                    "Once a maximum fragment length other than 2^14 has been successfully "
                            + "negotiated, the client and server MUST immediately begin fragmenting "
                            + "messages (including handshake messages) to ensure that no fragment "
                            + "larger than the negotiated length is sent.")
    @HandshakeCategory(SeverityLevel.LOW)
    @InteroperabilityCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.MEDIUM)
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
