/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.both.tls13.rfc8446;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.GenericReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.DynamicValueConstraints;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.ScopeExtensions;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.annotations.categories.AlertCategory;
import de.rub.nds.tlstest.framework.annotations.categories.ComplianceCategory;
import de.rub.nds.tlstest.framework.coffee4j.model.ModelFromScope;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.constants.TestEndpointType;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.DerivationType;
import de.rub.nds.tlstest.framework.model.ModelType;
import de.rub.nds.tlstest.framework.model.derivationParameter.AlertDerivation;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@RFC(number = 8446, section = "6. Alert Protocol")
public class AlertProtocol extends Tls13Test {

    @TlsTest(
            description =
                    "All the alerts listed in Section 6.2 MUST be sent with AlertLevel=fatal and MUST be treated as error alerts when received regardless of the AlertLevel in the message.")
    @ScopeExtensions(DerivationType.ALERT)
    @DynamicValueConstraints(
            affectedTypes = DerivationType.ALERT,
            methods = "isMeantToBeFatalLevel")
    @ComplianceCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.MEDIUM)
    @Tag("new")
    public void treatsFatalAlertsAsFatalHandshake(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace trace =
                runner.generateWorkflowTraceUntilSendingMessage(
                        WorkflowTraceType.HANDSHAKE, HandshakeMessageType.FINISHED);
        performFatalAlertWithWarningLevelTest(trace, runner, config);
    }

    @TlsTest(
            description =
                    "All the alerts listed in Section 6.2 MUST be sent with AlertLevel=fatal and MUST be treated as error alerts when received regardless of the AlertLevel in the message.")
    @ModelFromScope(baseModel = ModelType.CERTIFICATE)
    @ScopeExtensions(DerivationType.ALERT)
    @DynamicValueConstraints(
            affectedTypes = DerivationType.ALERT,
            methods = "isMeantToBeFatalLevel")
    @ComplianceCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.MEDIUM)
    @Tag("new")
    public void treatsFatalAlertsAsFatalPostHandshake(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace trace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        performFatalAlertWithWarningLevelTest(trace, runner, config);
    }

    @TlsTest(description = "Unknown Alert types MUST be treated as error alerts.")
    @ModelFromScope(baseModel = ModelType.CERTIFICATE)
    @ComplianceCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.MEDIUM)
    @Tag("new")
    public void treatsUnknownWarningAlertsAsFatalHandshake(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace trace =
                runner.generateWorkflowTraceUntilSendingMessage(
                        WorkflowTraceType.HANDSHAKE, HandshakeMessageType.FINISHED);
        peformUnknownWarningAlertTest(trace, runner, config);
    }

    @TlsTest(description = "Unknown Alert types MUST be treated as error alerts.")
    @ModelFromScope(baseModel = ModelType.CERTIFICATE)
    @ComplianceCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.MEDIUM)
    @Tag("new")
    public void treatsUnknownWarningAlertsAsFatalPostHandshake(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace trace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        peformUnknownWarningAlertTest(trace, runner, config);
    }

    @TlsTest(description = "Unknown Alert types MUST be treated as error alerts.")
    @ModelFromScope(baseModel = ModelType.CERTIFICATE)
    @ComplianceCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.MEDIUM)
    @Tag("new")
    public void treatsUnknownFatalAlertsAsFatalHandshake(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace trace =
                runner.generateWorkflowTraceUntilSendingMessage(
                        WorkflowTraceType.HANDSHAKE, HandshakeMessageType.FINISHED);
        peformUnknownFatalAlertTest(trace, runner, config);
    }

    @TlsTest(description = "Unknown Alert types MUST be treated as error alerts.")
    @ModelFromScope(baseModel = ModelType.CERTIFICATE)
    @ComplianceCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.MEDIUM)
    @Tag("new")
    public void treatsUnknownFatalAlertsAsFatalPostHandshake(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace trace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        peformUnknownFatalAlertTest(trace, runner, config);
    }

    @TlsTest(
            description =
                    "Each party MUST send a \"close_notify\" alert before closing its write side of the connection, unless it has already sent some error alert.")
    @ModelFromScope(baseModel = ModelType.CERTIFICATE)
    @ComplianceCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.MEDIUM)
    @Tag("new")
    public void sendsCloseNotify(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace trace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        AlertMessage alert = new AlertMessage();
        alert.setConfig(AlertLevel.WARNING, AlertDescription.CLOSE_NOTIFY);
        trace.addTlsAction(new SendAction(alert));
        trace.addTlsAction(new ReceiveAction(new AlertMessage()));

        runner.execute(trace, config)
                .validateFinal(
                        i -> {
                            AlertMessage receivedAlert =
                                    i.getWorkflowTrace()
                                            .getFirstReceivedMessage(AlertMessage.class);
                            assertNotNull("No alert has been received", receivedAlert);
                            Validator.testAlertDescription(
                                    i, AlertDescription.CLOSE_NOTIFY, receivedAlert);
                        });
    }

    private void peformUnknownFatalAlertTest(
            WorkflowTrace trace, WorkflowRunner runner, Config config) {
        catchOptionalPostHandshakeMessage(trace);
        AlertMessage alert = new AlertMessage();
        alert.setLevel(Modifiable.explicit(AlertLevel.FATAL.getValue()));
        alert.setDescription(Modifiable.explicit((byte) 200));
        trace.addTlsAction(new SendAction(alert));
        catchOptionalAlertResponse(trace, config);

        runner.execute(trace, config)
                .validateFinal(
                        i -> {
                            assertTrue(
                                    "The socket has not been closed for an unknown alert with level fatal",
                                    Validator.socketClosed(i));
                        });
    }

    private void peformUnknownWarningAlertTest(
            WorkflowTrace trace, WorkflowRunner runner, Config config) {
        catchOptionalPostHandshakeMessage(trace);
        AlertMessage alert = new AlertMessage();
        alert.setLevel(Modifiable.explicit(AlertLevel.FATAL.getValue()));
        alert.setDescription(Modifiable.explicit((byte) 200));
        trace.addTlsAction(new SendAction(alert));
        catchOptionalAlertResponse(trace, config);

        runner.execute(trace, config)
                .validateFinal(
                        i -> {
                            assertTrue(
                                    "The socket has not been closed for an unknown alert with level warning",
                                    Validator.socketClosed(i));
                        });
    }

    public boolean isMeantToBeFatalLevel(AlertDescription alert) {
        return alert != AlertDescription.CLOSE_NOTIFY
                && alert != AlertDescription.DECRYPTION_FAILED_RESERVED
                && alert != AlertDescription.DECOMPRESSION_FAILURE
                && alert != AlertDescription.NO_CERTIFICATE_RESERVED
                && alert != AlertDescription.EXPORT_RESTRICTION_RESERVED
                && alert != AlertDescription.USER_CANCELED
                && alert != AlertDescription.NO_RENEGOTIATION
                && alert != AlertDescription.CERTIFICATE_UNOBTAINABLE
                && alert != AlertDescription.BAD_CERTIFICATE_HASH_VALUE
                && alert.getValue() <= 120;
    }

    private void performFatalAlertWithWarningLevelTest(
            WorkflowTrace trace, WorkflowRunner runner, Config config) {
        catchOptionalPostHandshakeMessage(trace);
        AlertMessage alert = new AlertMessage();
        alert.setLevel(Modifiable.explicit(AlertLevel.WARNING.getValue()));
        alert.setDescription(
                Modifiable.explicit(
                        derivationContainer
                                .getDerivation(AlertDerivation.class)
                                .getSelectedValue()
                                .getValue()));
        trace.addTlsAction(new SendAction(alert));
        catchOptionalAlertResponse(trace, config);

        runner.execute(trace, config)
                .validateFinal(
                        i -> {
                            assertTrue(
                                    "The socket has not been closed for a fatal alert with level warning",
                                    Validator.socketClosed(i));
                        });
    }

    private void catchOptionalPostHandshakeMessage(WorkflowTrace trace) {
        if (context.getConfig().getTestEndpointMode() == TestEndpointType.SERVER) {
            trace.addTlsAction(new GenericReceiveAction());
        }
    }

    private void catchOptionalAlertResponse(WorkflowTrace trace, Config config) {
        // we usually read the socket state with a timeout to allow the library
        // to process our messages first - adding a GenericReceiveAction
        // which exceeds the full timeout is identical (albeit less efficient)
        config.setReceiveFinalTcpSocketStateWithTimeout(false);
        trace.addTlsAction(new GenericReceiveAction());
    }
}
