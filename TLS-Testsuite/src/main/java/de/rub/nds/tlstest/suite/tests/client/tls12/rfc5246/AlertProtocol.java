/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
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
import de.rub.nds.tlstest.framework.annotations.ScopeExtensions;
import de.rub.nds.tlstest.framework.annotations.TestDescription;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.annotations.categories.Interoperability;
import de.rub.nds.tlstest.framework.annotations.categories.Security;
import de.rub.nds.tlstest.framework.coffee4j.model.ModelFromScope;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.constants.TestResult;
import de.rub.nds.tlstest.framework.execution.AnnotatedStateContainer;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.DerivationType;
import de.rub.nds.tlstest.framework.model.ModelType;
import de.rub.nds.tlstest.framework.model.derivationParameter.AlertDerivation;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;

import static org.junit.Assert.assertEquals;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@RFC(number = 5264, section = "7.2.1 Closure Alerts")
@ClientTest
public class AlertProtocol extends Tls12Test {

    @TlsTest(description = "Unless some other fatal alert has been transmitted, each party is " +
            "required to send a close_notify alert before closing the write side " +
            "of the connection. The other party MUST respond with a close_notify " +
            "alert of its own and close down the connection immediately, " +
            "discarding any pending writes.")
    @Interoperability(SeverityLevel.MEDIUM)
    public void close_notify(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

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
                i.setResult(TestResult.PARTIALLY_SUCCEEDED);
                return;
            }
            assertEquals("Did not receive warning alert", AlertLevel.WARNING.getValue(), message.getLevel().getValue().byteValue());
            Validator.testAlertDescription(i, AlertDescription.CLOSE_NOTIFY, message);

        });
    }

    @TlsTest
    @RFC(number = 5264, section = "7.2.2 Error Alerts")
    @Security(SeverityLevel.CRITICAL)
    @ScopeExtensions(DerivationType.ALERT)
    @TestDescription("A Fatal Alert must terminate the connection")
    public void abortAfterFatalAlertServerHello(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        AlertDescription description = derivationContainer.getDerivation(AlertDerivation.class).getSelectedValue();

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsActions(
                new ReceiveAction(new AlertMessage())
        );

        AlertMessage alert = new AlertMessage();
        alert.setLevel(Modifiable.explicit(AlertLevel.FATAL.getValue()));
        alert.setDescription(Modifiable.explicit(description.getValue()));

        SendAction serverHelloAction = (SendAction)WorkflowTraceUtil.getFirstSendingActionForMessage(HandshakeMessageType.SERVER_HELLO, workflowTrace);
        serverHelloAction.getSendMessages().add(0, alert);

        runner.execute(workflowTrace, c).validateFinal(Validator::receivedFatalAlert);
    }

    @TlsTest
    @ModelFromScope(baseModel = ModelType.CERTIFICATE)
    @RFC(number = 5264, section = "7.2.2 Error Alerts")
    @Security(SeverityLevel.CRITICAL)
    @ScopeExtensions(DerivationType.ALERT)
    @TestDescription("A Fatal Alert must terminate the connection")
    public void abortAfterFatalAlertServerHelloDone(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        AlertDescription description = derivationContainer.getDerivation(AlertDerivation.class).getSelectedValue();

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsActions(
                new ReceiveAction(new AlertMessage())
        );

        AlertMessage alert = new AlertMessage();
        alert.setLevel(Modifiable.explicit(AlertLevel.FATAL.getValue()));
        alert.setDescription(Modifiable.explicit(description.getValue()));

        SendAction serverHelloAction = (SendAction)WorkflowTraceUtil.getFirstSendingActionForMessage(HandshakeMessageType.SERVER_HELLO, workflowTrace);
            serverHelloAction.getSendMessages().add(serverHelloAction.getSendMessages().size() - 1, alert);


        runner.execute(workflowTrace, c).validateFinal(Validator::receivedFatalAlert);
    }
}
