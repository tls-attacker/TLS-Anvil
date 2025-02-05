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

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.DynamicValueConstraints;
import de.rub.nds.anvilcore.annotation.IncludeParameter;
import de.rub.nds.anvilcore.coffee4j.model.ModelFromScope;
import de.rub.nds.anvilcore.constants.TestEndpointType;
import de.rub.nds.anvilcore.teststate.AnvilTestCase;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.GenericReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.derivationParameter.AlertDerivation;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
import java.util.List;
import org.junit.jupiter.api.Tag;

public class AlertProtocol extends Tls13Test {

    @AnvilTest(id = "8446-VkKqN54gN1")
    @IncludeParameter("ALERT")
    @DynamicValueConstraints(affectedIdentifiers = "ALERT", methods = "isMeantToBeFatalLevel")
    @Tag("new")
    public void treatsFatalAlertsAsFatalHandshake(AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);
        WorkflowTrace trace =
                runner.generateWorkflowTraceUntilSendingMessage(
                        WorkflowTraceType.HANDSHAKE, HandshakeMessageType.FINISHED);
        performFatalAlertWithWarningLevelTest(trace, runner, config);
    }

    @AnvilTest(id = "8446-k8Fht68Dq2")
    @ModelFromScope(modelType = "CERTIFICATE")
    @IncludeParameter("ALERT")
    @DynamicValueConstraints(affectedIdentifiers = "ALERT", methods = "isMeantToBeFatalLevel")
    @Tag("new")
    public void treatsFatalAlertsAsFatalPostHandshake(
            AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);
        WorkflowTrace trace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        performFatalAlertWithWarningLevelTest(trace, runner, config);
    }

    @AnvilTest(id = "8446-4vT4QZyhRd")
    @ModelFromScope(modelType = "CERTIFICATE")
    @Tag("new")
    public void treatsUnknownWarningAlertsAsFatalHandshake(
            AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);
        WorkflowTrace trace =
                runner.generateWorkflowTraceUntilSendingMessage(
                        WorkflowTraceType.HANDSHAKE, HandshakeMessageType.FINISHED);
        peformUnknownWarningAlertTest(trace, runner, config);
    }

    @AnvilTest(id = "8446-Q8Xknkk2vi")
    @ModelFromScope(modelType = "CERTIFICATE")
    @Tag("new")
    public void treatsUnknownWarningAlertsAsFatalPostHandshake(
            AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);
        WorkflowTrace trace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        peformUnknownWarningAlertTest(trace, runner, config);
    }

    @AnvilTest(id = "8446-zUe5jnQtoN")
    @ModelFromScope(modelType = "CERTIFICATE")
    @Tag("new")
    public void treatsUnknownFatalAlertsAsFatalHandshake(
            AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);
        WorkflowTrace trace =
                runner.generateWorkflowTraceUntilSendingMessage(
                        WorkflowTraceType.HANDSHAKE, HandshakeMessageType.FINISHED);
        peformUnknownFatalAlertTest(trace, runner, config);
    }

    @AnvilTest(id = "8446-PDB3U8CTKu")
    @ModelFromScope(modelType = "CERTIFICATE")
    @Tag("new")
    public void treatsUnknownFatalAlertsAsFatalPostHandshake(
            AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);
        WorkflowTrace trace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        peformUnknownFatalAlertTest(trace, runner, config);
    }

    @AnvilTest(id = "8446-V9hFSg6hoE")
    @ModelFromScope(modelType = "CERTIFICATE")
    @Tag("new")
    public void sendsCloseNotify(AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);
        WorkflowTrace trace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        AlertMessage alert = new AlertMessage();
        alert.setConfig(AlertLevel.WARNING, AlertDescription.CLOSE_NOTIFY);

        // TLS 1.3 forbids fragmented alerts
        Record unfragmentedRecord = new Record();
        unfragmentedRecord.setMaxRecordLengthConfig(2);
        SendAction sendAlert = new SendAction(alert);
        sendAlert.setConfiguredRecords(List.of(unfragmentedRecord));
        trace.addTlsAction(sendAlert);
        trace.addTlsAction(new ReceiveAction(new AlertMessage()));

        State state = runner.execute(trace, config);

        AlertMessage receivedAlert =
                state.getWorkflowTrace().getFirstReceivedMessage(AlertMessage.class);
        assertNotNull("No alert has been received", receivedAlert);
        Validator.testAlertDescription(
                state, testCase, AlertDescription.CLOSE_NOTIFY, receivedAlert);
    }

    private void peformUnknownFatalAlertTest(
            WorkflowTrace trace, WorkflowRunner runner, Config config) {
        catchOptionalPostHandshakeMessage(trace);
        AlertMessage alert = new AlertMessage();
        alert.setLevel(Modifiable.explicit(AlertLevel.FATAL.getValue()));
        alert.setDescription(Modifiable.explicit((byte) 200));
        trace.addTlsAction(new SendAction(alert));
        catchOptionalAlertResponse(trace, config);

        State state = runner.execute(trace, config);

        assertTrue(
                "The socket has not been closed for an unknown alert with level fatal",
                Validator.socketClosed(state));
    }

    private void peformUnknownWarningAlertTest(
            WorkflowTrace trace, WorkflowRunner runner, Config config) {
        catchOptionalPostHandshakeMessage(trace);
        AlertMessage alert = new AlertMessage();
        alert.setLevel(Modifiable.explicit(AlertLevel.FATAL.getValue()));
        alert.setDescription(Modifiable.explicit((byte) 200));
        trace.addTlsAction(new SendAction(alert));
        catchOptionalAlertResponse(trace, config);

        State state = runner.execute(trace, config);

        assertTrue(
                "The socket has not been closed for an unknown alert with level warning",
                Validator.socketClosed(state));
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
                        parameterCombination
                                .getParameter(AlertDerivation.class)
                                .getSelectedValue()
                                .getValue()));
        trace.addTlsAction(new SendAction(alert));
        catchOptionalAlertResponse(trace, config);

        State state = runner.execute(trace, config);

        assertTrue(
                "The socket has not been closed for a fatal alert with level warning",
                Validator.socketClosed(state));
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
