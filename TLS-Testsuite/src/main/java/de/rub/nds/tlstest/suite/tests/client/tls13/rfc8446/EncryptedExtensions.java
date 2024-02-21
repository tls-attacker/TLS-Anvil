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
import de.rub.nds.anvilcore.teststate.AnvilTestCase;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.MaxFragmentLength;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.EncryptedExtensionsMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.MaxFragmentLengthExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PaddingExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SupportedVersionsExtensionMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;

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

    @AnvilTest(id = "8446-X68SWFRBVS")
    public void sendSupportedVersionsExtensionInEE(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsActions(new ReceiveAction(new AlertMessage()));

        EncryptedExtensionsMessage ee =
                workflowTrace.getFirstSendMessage(EncryptedExtensionsMessage.class);
        ee.addExtension(new SupportedVersionsExtensionMessage());

        State state = runner.execute(workflowTrace, c);
        Validator.receivedFatalAlert(state, testCase);
        AlertMessage alert = state.getWorkflowTrace().getFirstReceivedMessage(AlertMessage.class);
        Validator.testAlertDescription(state, testCase, AlertDescription.ILLEGAL_PARAMETER, alert);
    }

    @AnvilTest(id = "8446-U5uSdqYohP")
    public void sendPaddingExtensionInEE(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsActions(new ReceiveAction(new AlertMessage()));

        EncryptedExtensionsMessage ee =
                workflowTrace.getFirstSendMessage(EncryptedExtensionsMessage.class);
        ee.addExtension(new PaddingExtensionMessage());

        State state = runner.execute(workflowTrace, c);

        Validator.receivedFatalAlert(state, testCase);
        AlertMessage alert = state.getWorkflowTrace().getFirstReceivedMessage(AlertMessage.class);
        Validator.testAlertDescription(state, testCase, AlertDescription.ILLEGAL_PARAMETER, alert);
    }

    @AnvilTest(id = "8446-34CYsV98Fs")
    @MethodCondition(method = "sentMaximumFragmentLength")
    public void invalidMaximumFragmentLength(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsActions(new ReceiveAction(new AlertMessage()));

        EncryptedExtensionsMessage encExt =
                workflowTrace.getFirstSendMessage(EncryptedExtensionsMessage.class);
        MaxFragmentLengthExtensionMessage malMaxFrag = new MaxFragmentLengthExtensionMessage();
        malMaxFrag.setMaxFragmentLength(Modifiable.explicit(new byte[] {5}));
        encExt.addExtension(malMaxFrag);

        State state = runner.execute(workflowTrace, c);
        Validator.receivedFatalAlert(state, testCase);

        WorkflowTrace trace = state.getWorkflowTrace();
        AlertMessage alert = trace.getLastReceivedMessage(AlertMessage.class);
        Validator.testAlertDescription(state, testCase, AlertDescription.ILLEGAL_PARAMETER, alert);
    }

    @AnvilTest(id = "8446-XDu7chdPTM")
    @MethodCondition(method = "sentMaximumFragmentLength")
    public void unrequestedMaximumFragmentLength(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);

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

        State state = runner.execute(workflowTrace, c);

        Validator.receivedFatalAlert(state, testCase);
        WorkflowTrace trace = state.getWorkflowTrace();
        AlertMessage alert = trace.getLastReceivedMessage(AlertMessage.class);
        Validator.testAlertDescription(state, testCase, AlertDescription.ILLEGAL_PARAMETER, alert);
    }
}
