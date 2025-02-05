/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.client.tls12.rfc5246;

import static org.junit.Assert.assertTrue;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.ClientTest;
import de.rub.nds.anvilcore.annotation.DynamicValueConstraints;
import de.rub.nds.anvilcore.annotation.IncludeParameter;
import de.rub.nds.anvilcore.coffee4j.model.ModelFromScope;
import de.rub.nds.anvilcore.teststate.AnvilTestCase;
import de.rub.nds.anvilcore.teststate.TestResult;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceResultUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.derivationParameter.AlertDerivation;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;

@ClientTest
public class AlertProtocol extends Tls12Test {

    // alerts must not be fragmented
    public boolean recordLengthAllowsModification(Integer lengthCandidate) {
        return lengthCandidate >= 50;
    }

    @AnvilTest(id = "5246-DjYR2JiJKn")
    @DynamicValueConstraints(
            affectedIdentifiers = "RECORD_LENGTH",
            methods = "recordLengthAllowsModification")
    public void closeNotifyInHandshake(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);

        AlertMessage alert = new AlertMessage();
        alert.setLevel(Modifiable.explicit(AlertLevel.WARNING.getValue()));
        alert.setDescription(Modifiable.explicit(AlertDescription.CLOSE_NOTIFY.getValue()));

        WorkflowTrace workflowTrace =
                runner.generateWorkflowTraceUntilSendingMessage(
                        WorkflowTraceType.HELLO, HandshakeMessageType.SERVER_HELLO_DONE);
        workflowTrace.getLastSendingAction().getSendMessages().add(alert);

        workflowTrace.addTlsActions(new ReceiveAction(new AlertMessage()));

        State state = runner.execute(workflowTrace, c);
        evaluateAlertTest(testCase, state);
    }

    @AnvilTest(id = "5246-e4Fsk3lp2z")
    @DynamicValueConstraints(
            affectedIdentifiers = "RECORD_LENGTH",
            methods = "recordLengthAllowsModification")
    public void closeNotifyPostHandshake(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);

        AlertMessage alert = new AlertMessage();
        alert.setLevel(Modifiable.explicit(AlertLevel.WARNING.getValue()));
        alert.setDescription(Modifiable.explicit(AlertDescription.CLOSE_NOTIFY.getValue()));

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        workflowTrace.getLastSendingAction().getSendMessages().add(alert);

        workflowTrace.addTlsActions(new ReceiveAction(new AlertMessage()));

        State state = runner.execute(workflowTrace, c);
        evaluateAlertTest(testCase, state);
    }

    private void evaluateAlertTest(AnvilTestCase testCase, State state) {
        WorkflowTrace trace = state.getWorkflowTrace();
        Validator.smartExecutedAsPlanned(state, testCase);

        AlertMessage message = trace.getLastReceivedMessage(AlertMessage.class);
        if (message == null && Validator.socketClosed(state)) {
            testCase.addAdditionalResultInfo("No CLOSE NOTIFY Alert received.");
            testCase.setTestResult(TestResult.CONCEPTUALLY_SUCCEEDED);
            return;
        }
        assertTrue("Socket has not been closed", Validator.socketClosed(state));
        Validator.receivedWarningAlert(state, testCase);
        Validator.testAlertDescription(state, testCase, AlertDescription.CLOSE_NOTIFY, message);
    }

    @AnvilTest(id = "5246-N8VwCXYaTF")
    @IncludeParameter("ALERT")
    @DynamicValueConstraints(
            affectedIdentifiers = "RECORD_LENGTH",
            methods = "recordLengthAllowsModification")
    public void abortAfterFatalAlertServerHello(WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);
        AlertDescription description =
                parameterCombination.getParameter(AlertDerivation.class).getSelectedValue();

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsActions(new ReceiveAction(new AlertMessage()));

        AlertMessage alert = new AlertMessage();
        alert.setLevel(Modifiable.explicit(AlertLevel.FATAL.getValue()));
        alert.setDescription(Modifiable.explicit(description.getValue()));

        SendAction serverHelloAction =
                (SendAction)
                        WorkflowTraceResultUtil.getFirstActionThatSent(
                                workflowTrace, HandshakeMessageType.SERVER_HELLO);
        serverHelloAction.getSendMessages().add(0, alert);

        State state = runner.execute(workflowTrace, c);
        assertTrue(
                "The socket has not been closed for an alert with level fatal",
                Validator.socketClosed(state));
    }

    @AnvilTest(id = "5246-rcBco3YXw8")
    @ModelFromScope(modelType = "CERTIFICATE")
    @IncludeParameter("ALERT")
    @DynamicValueConstraints(
            affectedIdentifiers = "RECORD_LENGTH",
            methods = "recordLengthAllowsModification")
    public void abortAfterFatalAlertServerHelloDone(WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);
        AlertDescription description =
                parameterCombination.getParameter(AlertDerivation.class).getSelectedValue();

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsActions(new ReceiveAction(new AlertMessage()));

        AlertMessage alert = new AlertMessage();
        alert.setLevel(Modifiable.explicit(AlertLevel.FATAL.getValue()));
        alert.setDescription(Modifiable.explicit(description.getValue()));

        SendAction serverHelloAction =
                (SendAction)
                        WorkflowTraceResultUtil.getFirstActionThatSent(
                                workflowTrace, HandshakeMessageType.SERVER_HELLO);
        serverHelloAction
                .getSendMessages()
                .add(serverHelloAction.getSendMessages().size() - 1, alert);

        State state = runner.execute(workflowTrace, c);
        assertTrue(
                "The socket has not been closed for an alert with level fatal",
                Validator.socketClosed(state));
    }
}
