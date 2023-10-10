/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.client.tls13.rfc8446;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.ClientTest;
import de.rub.nds.anvilcore.annotation.MethodCondition;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.MaxFragmentLength;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.EncryptedExtensionsMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.MaxFragmentLengthExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PaddingExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SupportedVersionsExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@ClientTest
public class EncryptedExtensions extends Tls13Test {

    public ConditionEvaluationResult sentMaximumFragmentLength() {
        if (context.getReceivedClientHelloMessage()
                        .getExtension(MaxFragmentLengthExtensionMessage.class)
                != null) {
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

    @AnvilTest
    public void sendSupportedVersionsExtensionInEE(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsActions(new ReceiveAction(new AlertMessage()));

        EncryptedExtensionsMessage ee =
                workflowTrace.getFirstSendMessage(EncryptedExtensionsMessage.class);
        ee.addExtension(new SupportedVersionsExtensionMessage());

        runner.execute(workflowTrace, c)
                .validateFinal(
                        i -> {
                            Validator.receivedFatalAlert(i);
                            AlertMessage alert =
                                    i.getWorkflowTrace()
                                            .getFirstReceivedMessage(AlertMessage.class);
                            Validator.testAlertDescription(
                                    i, AlertDescription.ILLEGAL_PARAMETER, alert);
                        });
    }

    @AnvilTest
    public void sendPaddingExtensionInEE(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsActions(new ReceiveAction(new AlertMessage()));

        EncryptedExtensionsMessage ee =
                workflowTrace.getFirstSendMessage(EncryptedExtensionsMessage.class);
        ee.addExtension(new PaddingExtensionMessage());

        runner.execute(workflowTrace, c)
                .validateFinal(
                        i -> {
                            Validator.receivedFatalAlert(i);
                            AlertMessage alert =
                                    i.getWorkflowTrace()
                                            .getFirstReceivedMessage(AlertMessage.class);
                            Validator.testAlertDescription(
                                    i, AlertDescription.ILLEGAL_PARAMETER, alert);
                        });
    }

    @AnvilTest
    @MethodCondition(method = "sentMaximumFragmentLength")
    public void invalidMaximumFragmentLength(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsActions(new ReceiveAction(new AlertMessage()));

        EncryptedExtensionsMessage encExt =
                workflowTrace.getFirstSendMessage(EncryptedExtensionsMessage.class);
        MaxFragmentLengthExtensionMessage malMaxFrag = new MaxFragmentLengthExtensionMessage();
        malMaxFrag.setMaxFragmentLength(Modifiable.explicit(new byte[] {5}));
        encExt.addExtension(malMaxFrag);

        runner.execute(workflowTrace, c)
                .validateFinal(
                        i -> {
                            Validator.receivedFatalAlert(i);

                            WorkflowTrace wtrace = i.getWorkflowTrace();
                            AlertMessage alert = wtrace.getLastReceivedMessage(AlertMessage.class);
                            Validator.testAlertDescription(
                                    i, AlertDescription.ILLEGAL_PARAMETER, alert);
                        });
    }

    @AnvilTest
    @MethodCondition(method = "sentMaximumFragmentLength")
    public void unrequestedMaximumFragmentLength(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        MaxFragmentLength unreqLen =
                getUnrequestedMaxFragLen(
                        context.getReceivedClientHelloMessage()
                                .getExtension(MaxFragmentLengthExtensionMessage.class));

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsActions(new ReceiveAction(new AlertMessage()));

        EncryptedExtensionsMessage encExt =
                workflowTrace.getFirstSendMessage(EncryptedExtensionsMessage.class);
        MaxFragmentLengthExtensionMessage malMaxFrag = new MaxFragmentLengthExtensionMessage();
        malMaxFrag.setMaxFragmentLength(Modifiable.explicit(new byte[] {unreqLen.getValue()}));
        encExt.addExtension(malMaxFrag);

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
}
