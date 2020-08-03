package de.rub.nds.tlstest.suite.tests.server.tls12.rfc5246;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.ServerTest;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.constants.TestStatus;
import de.rub.nds.tlstest.framework.execution.AnnotatedStateContainer;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;

import static org.junit.Assert.assertTrue;

@ServerTest
public class AlertProtocol extends Tls12Test {

    @TlsTest(description = "Unless some other fatal alert has been transmitted, each party is " +
            "required to send a close_notify alert before closing the write side " +
            "of the connection. The other party MUST respond with a close_notify " +
            "alert of its own and close down the connection immediately, " +
            "discarding any pending writes.")
    @RFC(number = 5264, section = "7.2.1 Closure Alerts")
    public void close_notify(WorkflowRunner runner) {
        Config c = this.getConfig();
        runner.replaceSupportedCiphersuites = true;

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
            assertTrue("Workflow could not be executed as planned", trace.smartExecutedAsPlanned());

            AlertMessage message = trace.getLastReceivedMessage(AlertMessage.class);
            if (message == null) {
                i.addAdditionalResultInfo("No close_notify alert received.");
                i.setStatus(TestStatus.PARTIALLY_SUCCEEDED);
                return;
            }
            Validator.receivedWarningAlert(i);
            Validator.testAlertDescription(i, AlertDescription.CLOSE_NOTIFY, message);

        });
    }



    @TlsTest(description = "Thus, any connection terminated with a fatal alert MUST NOT be resumed.", securitySeverity = SeverityLevel.CRITICAL)
    @RFC(number = 5264, section = "7.2.2 Error Alerts")
    public void abortAfterFatalAlert_sendBeforeCCS(WorkflowRunner runner) {
        Config c = this.getConfig();
        runner.replaceSupportedCiphersuites = true;
        runner.generateWorkflowTraceUntilSendingMessage(WorkflowTraceType.HANDSHAKE, ProtocolMessageType.CHANGE_CIPHER_SPEC);

        AnnotatedStateContainer container = new AnnotatedStateContainer();
        for (AlertDescription i : AlertDescription.values()) {
            AlertMessage alert = new AlertMessage();
            alert.setLevel(Modifiable.explicit(AlertLevel.FATAL.getValue()));
            alert.setDescription(Modifiable.explicit(i.getValue()));

            WorkflowTrace workflowTrace = new WorkflowTrace();
            workflowTrace.addTlsActions(
                    new SendAction(alert),
                    new SendAction(true, new ChangeCipherSpecMessage(), new FinishedMessage()),
                    new ReceiveAction(new AlertMessage())
            );

            runner.setStateModifier(s -> {
                s.addAdditionalTestInfo(i.name());
                return null;
            });
            container.addAll(runner.prepare(workflowTrace, c));
        }

        runner.execute(container).validateFinal(Validator::receivedFatalAlert);
    }

    @TlsTest(description = "Thus, any connection terminated with a fatal alert MUST NOT be resumed.", securitySeverity = SeverityLevel.CRITICAL)
    @RFC(number = 5264, section = "7.2.2 Error Alerts")
    public void abortAfterFatalAlert_sendAfterServerHelloDone(WorkflowRunner runner) {
        Config c = this.getConfig();
        runner.replaceSupportedCiphersuites = true;
        runner.generateWorkflowTrace(WorkflowTraceType.HELLO);

        AnnotatedStateContainer container = new AnnotatedStateContainer();
        for (AlertDescription i : AlertDescription.values()) {
            AlertMessage alert = new AlertMessage();
            alert.setLevel(Modifiable.explicit(AlertLevel.FATAL.getValue()));
            alert.setDescription(Modifiable.explicit(i.getValue()));

            WorkflowTrace workflowTrace = new WorkflowTrace();
            workflowTrace.addTlsActions(
                    new SendAction(alert),
                    new ReceiveAction(new AlertMessage())
            );

            runner.setStateModifier(s -> {
                s.addAdditionalTestInfo(i.name());
                return null;
            });
            container.addAll(runner.prepare(workflowTrace, c));
        }

        runner.execute(container).validateFinal(Validator::receivedFatalAlert);
    }
}
