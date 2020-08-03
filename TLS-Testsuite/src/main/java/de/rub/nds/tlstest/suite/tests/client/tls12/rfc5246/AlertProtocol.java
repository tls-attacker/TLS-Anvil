package de.rub.nds.tlstest.suite.tests.client.tls12.rfc5246;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.ClientTest;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.constants.TestStatus;
import de.rub.nds.tlstest.framework.execution.AnnotatedStateContainer;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;

import static org.junit.Assert.assertEquals;

@RFC(number = 5264, section = "7.2.1 Closure Alerts")
@ClientTest
public class AlertProtocol extends Tls12Test {

    @TlsTest(description = "Unless some other fatal alert has been transmitted, each party is " +
            "required to send a close_notify alert before closing the write side " +
            "of the connection. The other party MUST respond with a close_notify " +
            "alert of its own and close down the connection immediately, " +
            "discarding any pending writes.", interoperabilitySeverity = SeverityLevel.MEDIUM)
    public void close_notify(WorkflowRunner runner) {
        Config c = this.getConfig();
        runner.replaceSelectedCiphersuite = true;

        AlertMessage alert = new AlertMessage();
        alert.setLevel(Modifiable.explicit(AlertLevel.WARNING.getValue()));
        alert.setDescription(Modifiable.explicit(AlertDescription.CLOSE_NOTIFY.getValue()));

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                new ReceiveAction(new ClientHelloMessage()),
                new SendAction(alert),
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(workflowTrace, c).validateFinal(i -> {
            WorkflowTrace trace = i.getWorkflowTrace();
            Validator.executedAsPlanned(i);

            AlertMessage message = trace.getLastReceivedMessage(AlertMessage.class);
            if (message == null) {
                i.addAdditionalResultInfo("No close_notify alert received.");
                i.setStatus(TestStatus.PARTIALLY_SUCCEEDED);
                return;
            }
            assertEquals("Did not receive warning alert", AlertLevel.WARNING.getValue(), message.getLevel().getValue().byteValue());
            Validator.testAlertDescription(i, AlertDescription.CLOSE_NOTIFY, message);

        });
    }

    @TlsTest(description = "Thus, any connection terminated with a fatal alert MUST NOT be resumed.", securitySeverity = SeverityLevel.CRITICAL)
    @RFC(number = 5264, section = "7.2.2 Error Alerts")
    public void abortAfterFatalAlertServerHello(WorkflowRunner runner) {
        Config c = this.getConfig();
        AnnotatedStateContainer container = new AnnotatedStateContainer();

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsActions(
                new ReceiveAction(new AlertMessage())
        );

        for (AlertDescription i : AlertDescription.values()) {
            AlertMessage alert = new AlertMessage();
            alert.setLevel(Modifiable.explicit(AlertLevel.FATAL.getValue()));
            alert.setDescription(Modifiable.explicit(i.getValue()));

            runner.setStateModifier(t -> {
                t.addAdditionalTestInfo(String.format("Test with alert %s", i.name()));
                SendAction serverHelloAction = (SendAction)WorkflowTraceUtil.getFirstSendingActionForMessage(HandshakeMessageType.SERVER_HELLO, t.getWorkflowTrace());
                serverHelloAction.getSendMessages().add(0, alert);
                return null;
            });

            container.addAll(runner.prepare(workflowTrace, c));
        }

        runner.execute(container).validateFinal(Validator::receivedFatalAlert);
    }

    @TlsTest(description = "Thus, any connection terminated with a fatal alert MUST NOT be resumed.", securitySeverity = SeverityLevel.CRITICAL)
    @RFC(number = 5264, section = "7.2.2 Error Alerts")
    public void abortAfterFatalAlertServerHelloDone(WorkflowRunner runner) {
        Config c = this.getConfig();
        AnnotatedStateContainer container = new AnnotatedStateContainer();

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsActions(
                new ReceiveAction(new AlertMessage())
        );

        for (AlertDescription i : AlertDescription.values()) {
            AlertMessage alert = new AlertMessage();
            alert.setLevel(Modifiable.explicit(AlertLevel.FATAL.getValue()));
            alert.setDescription(Modifiable.explicit(i.getValue()));

            runner.setStateModifier(t -> {
                t.addAdditionalTestInfo(String.format("Test with alert %s", i.name()));
                SendAction serverHelloAction = (SendAction)WorkflowTraceUtil.getFirstSendingActionForMessage(HandshakeMessageType.SERVER_HELLO, t.getWorkflowTrace());
                serverHelloAction.getSendMessages().add(serverHelloAction.getSendMessages().size() - 1, alert);
                return null;
            });

            container.addAll(runner.prepare(workflowTrace, c));
        }

        runner.execute(container).validateFinal(Validator::receivedFatalAlert);
    }
}
