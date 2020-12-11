/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.server.tls12.rfc5246;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.MethodCondition;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.ScopeExtensions;
import de.rub.nds.tlstest.framework.annotations.ServerTest;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.annotations.categories.Security;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.constants.TestResult;
import de.rub.nds.tlstest.framework.execution.AnnotatedStateContainer;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.DerivationContainer;
import de.rub.nds.tlstest.framework.model.DerivationType;
import de.rub.nds.tlstest.framework.model.derivationParameter.AlertDerivation;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import de.rwth.swc.coffee4j.engine.characterization.delta.ImprovedDeltaDebugging;
import de.rwth.swc.coffee4j.junit.CombinatorialTest;
import de.rwth.swc.coffee4j.junit.provider.configuration.characterization.EnableFaultCharacterization;
import de.rwth.swc.coffee4j.junit.provider.configuration.reporter.Reporter;
import de.rwth.swc.coffee4j.model.report.PrintStreamExecutionReporter;
import java.util.Arrays;
import org.junit.jupiter.api.Tag;

import static org.junit.Assert.assertTrue;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@ServerTest
@Tag("alert")
@Execution(ExecutionMode.SAME_THREAD)
public class AlertProtocol extends Tls12Test {

    @TlsTest(description = "Unless some other fatal alert has been transmitted, each party is " +
            "required to send a close_notify alert before closing the write side " +
            "of the connection. The other party MUST respond with a close_notify " +
            "alert of its own and close down the connection immediately, " +
            "discarding any pending writes.")
    @RFC(number = 5246, section = "7.2.1 Closure Alerts")
    public void close_notify(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        AlertMessage alert = new AlertMessage();
        alert.setLevel(Modifiable.explicit(AlertLevel.WARNING.getValue()));
        alert.setDescription(Modifiable.explicit(AlertDescription.CLOSE_NOTIFY.getValue()));

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                new SendAction(new ClientHelloMessage(c)),
                new ReceiveTillAction(new ServerHelloDoneMessage()),
                new SendAction(alert),
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(workflowTrace, c).validateFinal(i -> {
            WorkflowTrace trace = i.getWorkflowTrace();
            assertTrue("Workflow could not be executed as planned", Validator.smartExecutedAsPlanned(trace));

            AlertMessage message = trace.getLastReceivedMessage(AlertMessage.class);
            if (message == null) {
                i.addAdditionalResultInfo("No close_notify alert received.");
                i.setResult(TestResult.PARTIALLY_SUCCEEDED);
                return;
            }
            Validator.receivedWarningAlert(i);
            Validator.testAlertDescription(i, AlertDescription.CLOSE_NOTIFY, message);

        });
    }

    
    @TlsTest(description = "Upon transmission or receipt of a fatal alert message, both" +
            "parties immediately close the connection.")
    @RFC(number = 5246, section = "7.2.2 Error Alerts")
    @Security(SeverityLevel.CRITICAL)
    @ScopeExtensions(DerivationType.ALERT)
    public void abortAfterFatalAlert_sendBeforeCCS(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace workflowTrace = runner.generateWorkflowTraceUntilSendingMessage(WorkflowTraceType.HANDSHAKE, ProtocolMessageType.CHANGE_CIPHER_SPEC);
        AlertDescription alertDescr = derivationContainer.getDerivation(AlertDerivation.class).getSelectedValue();

        AlertMessage alert = new AlertMessage();
        alert.setLevel(Modifiable.explicit(AlertLevel.FATAL.getValue()));
        alert.setDescription(Modifiable.explicit(alertDescr.getValue()));


        workflowTrace.addTlsActions(
            new SendAction(alert),
            new SendAction(ActionOption.MAY_FAIL, new ChangeCipherSpecMessage(), new FinishedMessage()),
            new ReceiveAction(new AlertMessage())
        );

        runner.execute(workflowTrace, c).validateFinal(Validator::receivedFatalAlert);
    }
    

    @TlsTest(description = "Upon transmission or receipt of a fatal alert message, both" +
            "parties immediately close the connection.")
    @RFC(number = 5246, section = "7.2.2 Error Alerts")
    @Security(SeverityLevel.CRITICAL)
    @ScopeExtensions(DerivationType.ALERT)
    public void abortAfterFatalAlert_sendAfterServerHelloDone(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        AlertDescription alertDescr = derivationContainer.getDerivation(AlertDerivation.class).getSelectedValue();

        AlertMessage alert = new AlertMessage();
        alert.setLevel(Modifiable.explicit(AlertLevel.FATAL.getValue()));
        alert.setDescription(Modifiable.explicit(alertDescr.getValue()));
        
        workflowTrace.addTlsActions(
                    new SendAction(alert),
                    new ReceiveAction(new AlertMessage())
        );
        
        runner.execute(workflowTrace,c).validateFinal(Validator::receivedFatalAlert);
    }
}


