/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.both.tls13.rfc8446;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.anvilcore.annotation.*;
import de.rub.nds.anvilcore.coffee4j.model.ModelFromScope;
import de.rub.nds.anvilcore.constants.TestEndpointType;
import de.rub.nds.anvilcore.teststate.AnvilTestCase;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.RecordCryptoComputations;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.*;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.derivationParameter.AdditionalPaddingLengthDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.ProtocolMessageTypeDerivation;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
import de.rub.nds.tlstest.suite.util.SharedModifiedRecords;
import java.util.List;
import org.junit.jupiter.api.Tag;

public class RecordProtocol extends Tls13Test {

    @AnvilTest(id = "8446-vbFRZNusey")
    public void invalidRecordContentType(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);
        WorkflowTrace trace;
        Record record = new Record();
        record.setContentType(Modifiable.explicit((byte) 0xff));
        if (context.getConfig().getTestEndpointMode() == TestEndpointType.SERVER) {
            trace = new WorkflowTrace();
            trace.addTlsAction(new SendAction(new ClientHelloMessage(c)));
        } else {
            trace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        }

        trace.addTlsAction(new ReceiveAction(new AlertMessage()));
        trace.getFirstAction(SendAction.class).setConfiguredRecords(List.of(record));

        State state = runner.execute(trace, c);

        Validator.receivedFatalAlert(state, testCase);
        AlertMessage alert = state.getWorkflowTrace().getFirstReceivedMessage(AlertMessage.class);
        Validator.testAlertDescription(state, testCase, AlertDescription.UNEXPECTED_MESSAGE, alert);
    }

    @AnvilTest(id = "8446-PN89HSERKp")
    @ModelFromScope(modelType = "CERTIFICATE")
    public void invalidRecordContentTypeAfterEncryption(
            AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);

        WorkflowTrace workflowTrace =
                runner.generateWorkflowTraceUntilSendingMessage(
                        WorkflowTraceType.HANDSHAKE, HandshakeMessageType.FINISHED);
        Record record = new Record();
        record.setContentType(Modifiable.explicit((byte) 0xff));
        FinishedMessage finished = new FinishedMessage();
        SendAction sendFinished = new SendAction(finished);
        sendFinished.setConfiguredRecords(List.of(record));
        workflowTrace.addTlsActions(sendFinished, new ReceiveAction(new AlertMessage()));

        State state = runner.execute(workflowTrace, c);
        Validator.receivedFatalAlert(state, testCase);

        AlertMessage alert = state.getWorkflowTrace().getFirstReceivedMessage(AlertMessage.class);
        Validator.testAlertDescription(state, testCase, AlertDescription.UNEXPECTED_MESSAGE, alert);
    }

    @AnvilTest(id = "8446-GXAiyehrdF")
    @ModelFromScope(modelType = "CERTIFICATE")
    @IncludeParameter("AUTH_TAG_BITMASK")
    public void invalidAuthTag(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);
        byte[] modificationBitmask = parameterCombination.buildBitmask();

        Record record = new Record();
        record.setComputations(new RecordCryptoComputations());
        record.getComputations().setAuthenticationTag(Modifiable.xor(modificationBitmask, 0));

        SendAction appData = new SendAction(new ApplicationMessage());
        appData.setConfiguredRecords(List.of(record));
        WorkflowTrace trace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        trace.addTlsActions(appData, new ReceiveAction(new AlertMessage()));

        State state = runner.execute(trace, c);
        Validator.receivedFatalAlert(state, testCase);

        AlertMessage alert = state.getWorkflowTrace().getFirstReceivedMessage(AlertMessage.class);
        Validator.testAlertDescription(state, testCase, AlertDescription.BAD_RECORD_MAC, alert);
    }

    @AnvilTest(id = "8446-n1veCSRVjQ")
    // Note that the additional byte is the encoded content type, which we also add
    @ModelFromScope(modelType = "CERTIFICATE")
    @ExcludeParameter("RECORD_LENGTH")
    public void sendRecordWithPlaintextOver2pow14(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);

        ApplicationMessage msg = new ApplicationMessage();
        Record overflowRecord = new Record();
        overflowRecord.setCleanProtocolMessageBytes(
                Modifiable.explicit(new byte[(int) (Math.pow(2, 14)) + 1]));
        SendAction sendOverflow = new SendAction(msg);
        sendOverflow.setConfiguredRecords(List.of(overflowRecord));

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        workflowTrace.addTlsActions(
                new ChangeConnectionTimeoutAction(
                        (long)
                                (context.getConfig().getAnvilTestConfig().getConnectionTimeout()
                                        * 2.5)),
                sendOverflow,
                new ReceiveAction(new AlertMessage()));

        State state = runner.execute(workflowTrace, c);
        Validator.receivedFatalAlert(state, testCase);
        AlertMessage alert = state.getWorkflowTrace().getFirstReceivedMessage(AlertMessage.class);
        Validator.testAlertDescription(state, testCase, AlertDescription.RECORD_OVERFLOW, alert);
    }

    public boolean recordLengthAllowsModification(Integer lengthCandidate) {
        return lengthCandidate >= 50;
    }

    @AnvilTest(id = "8446-GNEMTQXXpq")
    @ModelFromScope(modelType = "CERTIFICATE")
    @IncludeParameters({
        @IncludeParameter("CIPHERTEXT_BITMASK"),
        @IncludeParameter("APP_MSG_LENGHT")
    })
    @DynamicValueConstraints(
            affectedIdentifiers = "RECORD_LENGTH",
            methods = "recordLengthAllowsModification")
    public void invalidCiphertext(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);
        byte[] modificationBitmask = parameterCombination.buildBitmask();

        Record record = new Record();
        record.setComputations(new RecordCryptoComputations());
        record.getComputations().setCiphertext(Modifiable.xor(modificationBitmask, 0));

        SendAction appData = new SendAction(new ApplicationMessage());
        appData.setConfiguredRecords(List.of(record));
        WorkflowTrace trace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        trace.addTlsActions(appData, new ReceiveAction(new AlertMessage()));

        State state = runner.execute(trace, c);

        Validator.receivedFatalAlert(state, testCase);
        AlertMessage alert = state.getWorkflowTrace().getFirstReceivedMessage(AlertMessage.class);
        Validator.testAlertDescription(state, testCase, AlertDescription.BAD_RECORD_MAC, alert);
    }

    @AnvilTest(id = "8446-i9pq4Yt8pz")
    @ModelFromScope(modelType = "CERTIFICATE")
    @DynamicValueConstraints(
            affectedIdentifiers = "RECORD_LENGTH",
            methods = "isReasonableRecordSize")
    @IncludeParameter("ADDITIONAL_PADDING_LENGTH")
    public void acceptsOptionalPadding(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);
        int selectedPaddingLength =
                parameterCombination
                        .getParameter(AdditionalPaddingLengthDerivation.class)
                        .getSelectedValue();
        if (selectedPaddingLength >= 100) {
            applyTimeoutMultiplier(c, 1.5);
        }
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);

        State state = runner.execute(workflowTrace, c);

        Validator.executedAsPlanned(state, testCase);
    }

    public boolean isReasonableRecordSize(Integer recordSize) {
        // using very small records significantly increases reponse time of some SUTs
        return recordSize >= 50;
    }

    public void applyTimeoutMultiplier(Config c, double multiplier) {
        int baseTimeout = context.getConfig().getAnvilTestConfig().getConnectionTimeout();
        c.getDefaultClientConnection().setTimeout((int) (baseTimeout * multiplier));
        c.getDefaultServerConnection().setTimeout((int) (baseTimeout * multiplier));
    }

    @AnvilTest(id = "8446-BkyuGXzztX")
    @ModelFromScope(modelType = "CERTIFICATE")
    @ExcludeParameter("RECORD_LENGTH")
    public void sendRecordWithCiphertextOver2pow14plus256(
            AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);

        applyTimeoutMultiplier(c, 2.5);

        Record overflowRecord = new Record();
        overflowRecord.setProtocolMessageBytes(
                Modifiable.explicit(new byte[(int) (Math.pow(2, 14)) + 257]));
        // add dummy Application Message
        SendAction sendOverflow = new SendAction(new ApplicationMessage());
        sendOverflow.setConfiguredRecords(List.of(overflowRecord));

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        workflowTrace.addTlsActions(sendOverflow, new ReceiveAction(new AlertMessage()));

        State state = runner.execute(workflowTrace, c);

        Validator.receivedFatalAlert(state, testCase);
        AlertMessage alert = state.getWorkflowTrace().getFirstReceivedMessage(AlertMessage.class);
        Validator.testAlertDescription(state, testCase, AlertDescription.RECORD_OVERFLOW, alert);
    }

    @AnvilTest(id = "8446-aUT8tc8oYz")
    @ModelFromScope(modelType = "CERTIFICATE")
    @IncludeParameter("PROTOCOL_MESSAGE_TYPE")
    @Tag("emptyRecord")
    public void sendEmptyRecord(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);
        ProtocolMessageType selectedRecordContentType =
                parameterCombination
                        .getParameter(ProtocolMessageTypeDerivation.class)
                        .getSelectedValue();
        ApplicationMessage appMsg = new ApplicationMessage();

        Record r = new Record();
        r.setContentType(Modifiable.explicit(selectedRecordContentType.getValue()));
        r.setProtocolMessageBytes(Modifiable.explicit(new byte[0]));
        r.setMaxRecordLengthConfig(0);
        SendAction sendAction = new SendAction(appMsg);
        sendAction.setConfiguredRecords(List.of(r));

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        workflowTrace.addTlsActions(sendAction, new ReceiveAction(new AlertMessage()));

        State state = runner.execute(workflowTrace, c);
        Validator.receivedFatalAlert(state, testCase);
    }

    @AnvilTest(id = "8446-BSsVDoM82Z")
    @ModelFromScope(modelType = "CERTIFICATE")
    public void sendZeroLengthApplicationRecord(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);
        SendAction sendAction = SharedModifiedRecords.getZeroLengthRecordAction();

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        int baseTimeout = context.getConfig().getAnvilTestConfig().getConnectionTimeout();
        if (context.getFeatureExtractionResult().getClosedAfterAppDataDelta() > 0
                && context.getFeatureExtractionResult().getClosedAfterAppDataDelta()
                        < context.getConfig().getAnvilTestConfig().getConnectionTimeout()) {
            baseTimeout = (int) context.getFeatureExtractionResult().getClosedAfterAppDataDelta();
        }
        final int reducedTimeout = baseTimeout / 2;
        ChangeConnectionTimeoutAction changeTimeoutAction =
                new ChangeConnectionTimeoutAction(reducedTimeout);
        workflowTrace.addTlsActions(changeTimeoutAction, sendAction, new GenericReceiveAction());

        State state = runner.execute(workflowTrace, c);

        Validator.executedAsPlanned(state, testCase);
        AlertMessage msg = state.getWorkflowTrace().getFirstReceivedMessage(AlertMessage.class);
        testCase.addAdditionalResultInfo("Evaluated with timeout " + reducedTimeout);
        if (context.getFeatureExtractionResult().getClosedAfterAppDataDelta() > 0) {
            assertNull(msg, "Received alert message");
            assertFalse(Validator.socketClosed(state), "Socket was closed");
        } else {
            if (msg != null) {
                assertEquals(
                        AlertDescription.CLOSE_NOTIFY.getValue(),
                        (byte) msg.getDescription().getValue(),
                        "SUT sent an alert that was not a Close Notify");
            }
        }
    }

    @AnvilTest(id = "8446-EmE5eWBxE7")
    @Tag("new")
    public void sendEncryptedHandshakeRecordWithNoNonZeroOctet(
            AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);
        Record record = getRecordWithOnlyZeroOctets();

        WorkflowTrace trace =
                runner.generateWorkflowTraceUntilSendingMessage(
                        WorkflowTraceType.HANDSHAKE, HandshakeMessageType.FINISHED);
        trace.addTlsAction(new SendAction(new FinishedMessage()));
        trace.addTlsAction(new ReceiveAction(new AlertMessage()));
        // define modified record for finished
        ((SendAction) trace.getLastSendingAction()).setConfiguredRecords(List.of(record));

        State state = runner.execute(trace, config);

        Validator.receivedFatalAlert(state, testCase);
        Validator.testAlertDescription(state, testCase, AlertDescription.UNEXPECTED_MESSAGE);
    }

    @AnvilTest(id = "8446-hKUhsUFCnx")
    @ModelFromScope(modelType = "CERTIFICATE")
    @Tag("new")
    public void sendEncryptedAppRecordWithNoNonZeroOctet(
            AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);
        Record record = getRecordWithOnlyZeroOctets();

        WorkflowTrace trace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        trace.addTlsAction(new SendAction(new ApplicationMessage()));
        trace.addTlsAction(new ReceiveAction(new AlertMessage()));
        // define modified record for finished
        ((SendAction) trace.getLastSendingAction()).setConfiguredRecords(List.of(record));

        State state = runner.execute(trace, config);

        Validator.receivedFatalAlert(state, testCase);
        Validator.testAlertDescription(state, testCase, AlertDescription.UNEXPECTED_MESSAGE);
    }

    @AnvilTest(id = "8446-V3SF3rXAAW")
    @Tag("new")
    public void checkMinimumRecordProtocolVersions(AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        State state = runner.execute(workflowTrace, config);

        Validator.executedAsPlanned(state, testCase);
        testReceivedRecordVersions(state.getWorkflowTrace());
    }

    private Record getRecordWithOnlyZeroOctets() {
        Record record = new Record();
        record.setComputations(new RecordCryptoComputations());
        record.getComputations()
                .setPlainRecordBytes(Modifiable.explicit(new byte[] {0x00, 0x00, 0x00, 0x00}));
        return record;
    }

    private void testReceivedRecordVersions(WorkflowTrace executedTrace) {
        for (ReceivingAction receiving : executedTrace.getReceivingActions()) {
            for (Record record : receiving.getReceivedRecords()) {
                assertFalse(
                        record.getProtocolVersion().getValue()[0] < 0x03,
                        "Peer sent a record with Protocol Version below 0x03 00");
            }
        }
    }
}
