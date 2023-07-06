/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.both.tls13.rfc8446;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.KeyUpdateRequest;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.protocol.message.KeyUpdateMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.annotations.categories.AlertCategory;
import de.rub.nds.tlstest.framework.annotations.categories.ComplianceCategory;
import de.rub.nds.tlstest.framework.annotations.categories.HandshakeCategory;
import de.rub.nds.tlstest.framework.annotations.categories.InteroperabilityCategory;
import de.rub.nds.tlstest.framework.annotations.categories.RecordLayerCategory;
import de.rub.nds.tlstest.framework.coffee4j.model.ModelFromScope;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.TlsModelType;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@RFC(number = 8446, section = "4.6.3.  Key and Initialization Vector Update")
public class KeyUpdate extends Tls13Test {

    @TlsTest(
            description =
                    "Implementations "
                            + "that receive a KeyUpdate message prior to receiving a Finished "
                            + "message MUST terminate the connection with an \"unexpected_message\" "
                            + "alert.")
    @ModelFromScope(baseModel = TlsModelType.CERTIFICATE)
    @HandshakeCategory(SeverityLevel.HIGH)
    @ComplianceCategory(SeverityLevel.HIGH)
    @AlertCategory(SeverityLevel.MEDIUM)
    @Tag("new")
    public void sendKeyUpdateBeforeFinished(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        config.setDefaultKeyUpdateRequestMode(KeyUpdateRequest.UPDATE_REQUESTED);

        WorkflowTrace workflowTrace =
                runner.generateWorkflowTraceUntilSendingMessage(
                        WorkflowTraceType.HANDSHAKE, HandshakeMessageType.FINISHED);
        workflowTrace.addTlsAction(new SendAction(new KeyUpdateMessage()));
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));

        runner.execute(workflowTrace, config)
                .validateFinal(
                        i -> {
                            Validator.receivedFatalAlert(i);
                            Validator.testAlertDescription(i, AlertDescription.UNEXPECTED_MESSAGE);
                        });
    }

    @TlsTest(
            description =
                    "request_update:  Indicates whether the recipient of the KeyUpdate "
                            + "should respond with its own KeyUpdate.  If an implementation "
                            + "receives any other value, it MUST terminate the connection with an "
                            + "\"illegal_parameter\" alert.")
    @ComplianceCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.MEDIUM)
    @Tag("new")
    public void sendUnknownRequestMode(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        KeyUpdateMessage keyUpdate = new KeyUpdateMessage();
        keyUpdate.setRequestMode(Modifiable.explicit((byte) 0x03));
        workflowTrace.addTlsAction(new SendAction(keyUpdate));
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));

        runner.execute(workflowTrace, config)
                .validateFinal(
                        i -> {
                            Validator.receivedFatalAlert(i);
                            Validator.testAlertDescription(i, AlertDescription.ILLEGAL_PARAMETER);
                        });
    }

    @TlsTest(
            description =
                    "If the request_update field is set to \"update_requested\", then the receiver MUST send a KeyUpdate of its own with request_update set to \"update_not_requested\" prior to sending its next Application Data record. [...]"
                            + "Both sender and receiver MUST encrypt their KeyUpdate messages with "
                            + "the old keys.")
    @InteroperabilityCategory(SeverityLevel.HIGH)
    @ComplianceCategory(SeverityLevel.HIGH)
    @RecordLayerCategory(SeverityLevel.HIGH)
    @Tag("new")
    public void respondsWithValidKeyUpdate(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        config.setDefaultKeyUpdateRequestMode(KeyUpdateRequest.UPDATE_REQUESTED);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        KeyUpdateMessage keyUpdate = new KeyUpdateMessage();
        workflowTrace.addTlsAction(new SendAction(keyUpdate));
        workflowTrace.addTlsAction(new ReceiveAction(new KeyUpdateMessage()));

        runner.execute(workflowTrace, config)
                .validateFinal(
                        i -> {
                            Validator.executedAsPlanned(i);
                            KeyUpdateMessage receivedKeyUpdate =
                                    i.getWorkflowTrace()
                                            .getLastReceivedMessage(KeyUpdateMessage.class);
                            assertNotNull(
                                    "Did not receive a KeyUpdate response", receivedKeyUpdate);
                            assertEquals(
                                    "Peer did not set the correct KeyUpdate mode",
                                    (byte) KeyUpdateRequest.UPDATE_NOT_REQUESTED.getValue(),
                                    (byte) receivedKeyUpdate.getRequestMode().getValue());
                            for (Record record :
                                    workflowTrace.getLastReceivingAction().getReceivedRecords()) {
                                if (record.getContentMessageType()
                                        == ProtocolMessageType.HANDSHAKE) {
                                    assertTrue(
                                            "Invalid authentication tag for received KeyUpdateMessage",
                                            ((Record) record)
                                                    .getComputations()
                                                    .getAuthenticationTagValid());
                                }
                            }
                        });
    }

    @TlsTest(
            description =
                    "Upon receiving a KeyUpdate, the receiver MUST update " + "its receiving keys.")
    @InteroperabilityCategory(SeverityLevel.HIGH)
    @ComplianceCategory(SeverityLevel.HIGH)
    @RecordLayerCategory(SeverityLevel.HIGH)
    @Tag("new")
    public void appDataUnderNewKeysSucceeds(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        config.setDefaultKeyUpdateRequestMode(KeyUpdateRequest.UPDATE_REQUESTED);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        KeyUpdateMessage keyUpdate = new KeyUpdateMessage();
        workflowTrace.addTlsAction(new SendAction(keyUpdate));
        workflowTrace.addTlsAction(new ReceiveAction(new KeyUpdateMessage()));
        workflowTrace.addTlsAction(new SendAction(new ApplicationMessage()));
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));
        runner.execute(workflowTrace, config)
                .validateFinal(
                        i -> {
                            WorkflowTrace trace = i.getWorkflowTrace();
                            assertTrue(
                                    "Did not receive a KeyUpdate in response",
                                    WorkflowTraceUtil.didReceiveMessage(
                                            HandshakeMessageType.KEY_UPDATE, trace));
                            AlertMessage msg = trace.getFirstReceivedMessage(AlertMessage.class);
                            assertNull("Received alert message", msg);
                            assertFalse("Socket was closed", Validator.socketClosed(i));
                        });
    }
}
