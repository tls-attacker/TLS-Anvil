/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.both.tls13.rfc8446;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.coffee4j.model.ModelFromScope;
import de.rub.nds.anvilcore.teststate.AnvilTestCase;
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
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceResultUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
import org.junit.jupiter.api.Tag;

public class KeyUpdate extends Tls13Test {

    @AnvilTest(id = "8446-KAEXNq6tsi")
    @ModelFromScope(modelType = "CERTIFICATE")
    @Tag("new")
    public void sendKeyUpdateBeforeFinished(AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);
        config.setDefaultKeyUpdateRequestMode(KeyUpdateRequest.UPDATE_REQUESTED);

        WorkflowTrace workflowTrace =
                runner.generateWorkflowTraceUntilSendingMessage(
                        WorkflowTraceType.HANDSHAKE, HandshakeMessageType.FINISHED);
        workflowTrace.addTlsAction(new SendAction(new KeyUpdateMessage()));
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));

        State state = runner.execute(workflowTrace, config);

        Validator.receivedFatalAlert(state, testCase);
        Validator.testAlertDescription(state, testCase, AlertDescription.UNEXPECTED_MESSAGE);
    }

    @AnvilTest(id = "8446-Dy4H1oQ8bc")
    @Tag("new")
    public void sendUnknownRequestMode(AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        KeyUpdateMessage keyUpdate = new KeyUpdateMessage();
        keyUpdate.setRequestMode(Modifiable.explicit((byte) 0x03));
        workflowTrace.addTlsAction(new SendAction(keyUpdate));
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));

        State state = runner.execute(workflowTrace, config);

        Validator.receivedFatalAlert(state, testCase);
        Validator.testAlertDescription(state, testCase, AlertDescription.ILLEGAL_PARAMETER);
    }

    @AnvilTest(id = "8446-J6tVdjJCzF")
    @Tag("new")
    public void respondsWithValidKeyUpdate(AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);
        config.setDefaultKeyUpdateRequestMode(KeyUpdateRequest.UPDATE_REQUESTED);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        KeyUpdateMessage keyUpdate = new KeyUpdateMessage();
        workflowTrace.addTlsAction(new SendAction(keyUpdate));
        workflowTrace.addTlsAction(new ReceiveAction(new KeyUpdateMessage()));

        State state = runner.execute(workflowTrace, config);
        Validator.executedAsPlanned(state, testCase);
        KeyUpdateMessage receivedKeyUpdate =
                state.getWorkflowTrace().getLastReceivedMessage(KeyUpdateMessage.class);
        assertNotNull(receivedKeyUpdate, "Did not receive a KeyUpdate response");
        assertEquals(
                (byte) KeyUpdateRequest.UPDATE_NOT_REQUESTED.getValue(),
                (byte) receivedKeyUpdate.getRequestMode().getValue(),
                "Peer did not set the correct KeyUpdate mode");
        for (Record record : workflowTrace.getLastReceivingAction().getReceivedRecords()) {
            if (record.getContentMessageType() == ProtocolMessageType.HANDSHAKE) {
                assertTrue(
                        record.getComputations().getAuthenticationTagValid(),
                        "Invalid authentication tag for received KeyUpdateMessage");
            }
        }
    }

    @AnvilTest(id = "8446-fFh7mHrXow")
    @Tag("new")
    public void appDataUnderNewKeysSucceeds(WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);
        config.setDefaultKeyUpdateRequestMode(KeyUpdateRequest.UPDATE_REQUESTED);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        KeyUpdateMessage keyUpdate = new KeyUpdateMessage();
        workflowTrace.addTlsAction(new SendAction(keyUpdate));
        workflowTrace.addTlsAction(new ReceiveAction(new KeyUpdateMessage()));
        workflowTrace.addTlsAction(new SendAction(new ApplicationMessage()));
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));
        State state = runner.execute(workflowTrace, config);
        WorkflowTrace trace = state.getWorkflowTrace();
        assertTrue(
                WorkflowTraceResultUtil.didReceiveMessage(trace, HandshakeMessageType.KEY_UPDATE),
                "Did not receive a KeyUpdate in response");
        AlertMessage msg = trace.getFirstReceivedMessage(AlertMessage.class);
        if (msg == null
                || msg.getDescription().getValue() != AlertDescription.CLOSE_NOTIFY.getValue()) {
            assertNull(msg, "Received alert message that was not a close notify.");
            assertFalse(Validator.socketClosed(state), "Socket was closed");
        }
    }
}
