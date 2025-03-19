/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.server.tls12.rfc5246;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.DynamicValueConstraints;
import de.rub.nds.anvilcore.annotation.IncludeParameter;
import de.rub.nds.anvilcore.annotation.ServerTest;
import de.rub.nds.anvilcore.teststate.AnvilTestCase;
import de.rub.nds.anvilcore.teststate.TestResult;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.derivationParameter.AlertDerivation;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

@ServerTest
@Tag("alert")
@Execution(ExecutionMode.SAME_THREAD)
public class AlertProtocol extends Tls12Test {

    // alerts must not be fragmented
    public boolean recordLengthAllowsModification(Integer lengthCandidate) {
        return lengthCandidate >= 50;
    }

    @AnvilTest(id = "5246-ANzf57gCyp")
    @DynamicValueConstraints(
            affectedIdentifiers = "RECORD_LENGTH",
            methods = "recordLengthAllowsModification")
    public void closeNotify(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);

        AlertMessage alert = new AlertMessage();
        alert.setLevel(Modifiable.explicit(AlertLevel.WARNING.getValue()));
        alert.setDescription(Modifiable.explicit(AlertDescription.CLOSE_NOTIFY.getValue()));

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                new SendAction(new ClientHelloMessage(c)),
                new ReceiveTillAction(new ServerHelloDoneMessage()),
                new SendAction(alert),
                new ReceiveAction(new AlertMessage()));

        State state = runner.execute(workflowTrace, c);

        WorkflowTrace trace = state.getWorkflowTrace();
        Validator.smartExecutedAsPlanned(state, testCase);

        AlertMessage message = trace.getLastReceivedMessage(AlertMessage.class);
        if (message == null && Validator.socketClosed(state)) {
            testCase.addAdditionalResultInfo("No close_notify alert received.");
            testCase.setTestResult(TestResult.CONCEPTUALLY_SUCCEEDED);
            return;
        }
        assertTrue(Validator.socketClosed(state), "Socket has not been closed");
        Validator.receivedWarningAlert(state, testCase);
        Validator.testAlertDescription(state, testCase, AlertDescription.CLOSE_NOTIFY, message);
    }

    @AnvilTest(id = "5246-fGCWkS7TDf")
    @IncludeParameter("ALERT")
    @DynamicValueConstraints(
            affectedIdentifiers = "RECORD_LENGTH",
            methods = "recordLengthAllowsModification")
    public void abortAfterFatalAlert_sendBeforeCCS(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);
        WorkflowTrace workflowTrace =
                runner.generateWorkflowTraceUntilSendingMessage(
                        WorkflowTraceType.HANDSHAKE, ProtocolMessageType.CHANGE_CIPHER_SPEC);
        AlertDescription alertDescr =
                parameterCombination.getParameter(AlertDerivation.class).getSelectedValue();

        AlertMessage alert = new AlertMessage();
        alert.setLevel(Modifiable.explicit(AlertLevel.FATAL.getValue()));
        alert.setDescription(Modifiable.explicit(alertDescr.getValue()));

        workflowTrace.addTlsActions(
                new SendAction(alert),
                new SendAction(
                        ActionOption.MAY_FAIL,
                        new ChangeCipherSpecMessage(),
                        new FinishedMessage()),
                new ReceiveAction(new AlertMessage()));

        State state = runner.execute(workflowTrace, c);

        if (Validator.socketClosed(state)) {
            testCase.setTestResult(TestResult.STRICTLY_SUCCEEDED);
        } // TODO does that not always succeed? not set gets treated as succeeded
    }

    @AnvilTest(id = "5246-hD2QPXyAHw")
    @IncludeParameter("ALERT")
    @DynamicValueConstraints(
            affectedIdentifiers = "RECORD_LENGTH",
            methods = "recordLengthAllowsModification")
    public void abortAfterFatalAlert_sendAfterServerHelloDone(
            AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        AlertDescription alertDescr =
                parameterCombination.getParameter(AlertDerivation.class).getSelectedValue();

        AlertMessage alert = new AlertMessage();
        alert.setLevel(Modifiable.explicit(AlertLevel.FATAL.getValue()));
        alert.setDescription(Modifiable.explicit(alertDescr.getValue()));

        workflowTrace.addTlsActions(new SendAction(alert), new ReceiveAction(new AlertMessage()));

        State state = runner.execute(workflowTrace, c);

        if (Validator.socketClosed(state)) {
            testCase.setTestResult(TestResult.STRICTLY_SUCCEEDED);
        }
    }
}
