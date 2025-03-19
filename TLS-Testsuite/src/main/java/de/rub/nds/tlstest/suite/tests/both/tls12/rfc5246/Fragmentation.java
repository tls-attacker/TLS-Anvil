/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.both.tls12.rfc5246;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.ExcludeParameter;
import de.rub.nds.anvilcore.annotation.NonCombinatorialAnvilTest;
import de.rub.nds.anvilcore.coffee4j.model.ModelFromScope;
import de.rub.nds.anvilcore.teststate.AnvilTestCase;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ChangeConnectionTimeoutAction;
import de.rub.nds.tlsattacker.core.workflow.action.GenericReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.EnforcedSenderRestriction;
import de.rub.nds.tlstest.framework.constants.AssertMsgs;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import de.rub.nds.tlstest.suite.util.SharedModifiedRecords;
import java.util.List;
import org.junit.jupiter.api.Tag;

public class Fragmentation extends Tls12Test {

    @AnvilTest(id = "5246-bXbN8uEo2c")
    @EnforcedSenderRestriction
    public void sendZeroLengthRecord_CCS(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);
        c.setUseAllProvidedRecords(true);

        Record r = new Record();
        r.setContentMessageType(ProtocolMessageType.CHANGE_CIPHER_SPEC);
        r.setMaxRecordLengthConfig(0);
        SendAction sendAction = new SendAction(new ChangeCipherSpecMessage());
        sendAction.setConfiguredRecords(List.of(r));

        WorkflowTrace workflowTrace =
                runner.generateWorkflowTraceUntilSendingMessage(
                        WorkflowTraceType.HANDSHAKE, ProtocolMessageType.CHANGE_CIPHER_SPEC);
        workflowTrace.addTlsActions(
                sendAction,
                new SendAction(ActionOption.MAY_FAIL, new FinishedMessage()),
                new ReceiveAction(new AlertMessage()));

        State state = runner.execute(workflowTrace, c);
        Validator.receivedFatalAlert(state, testCase);
    }

    @AnvilTest(id = "5246-swjhCGVQMb")
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

        WorkflowTrace trace = state.getWorkflowTrace();
        assertTrue(trace.executedAsPlanned(), AssertMsgs.WORKFLOW_NOT_EXECUTED);

        AlertMessage msg = trace.getFirstReceivedMessage(AlertMessage.class);
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

    @AnvilTest(id = "5246-q5y1zcoCCW")
    @ModelFromScope(modelType = "CERTIFICATE")
    @Tag("emptyRecord")
    public void sendEmptyApplicationRecord(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);

        ApplicationMessage appMsg = new ApplicationMessage();

        Record r = new Record();
        r.setContentMessageType(ProtocolMessageType.APPLICATION_DATA);
        r.setMaxRecordLengthConfig(0);
        r.setProtocolMessageBytes(Modifiable.explicit(new byte[0]));
        SendAction sendAction = new SendAction(appMsg);
        sendAction.setConfiguredRecords(List.of(r));

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        workflowTrace.addTlsActions(sendAction, new ReceiveAction(new AlertMessage()));

        State state = runner.execute(workflowTrace, c);
        Validator.receivedFatalAlert(state, testCase);
    }

    @AnvilTest(id = "5246-5JmcCtfFY3")
    @Tag("emptyRecord")
    public void sendEmptyFinishedRecord(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);

        Record r = new Record();
        r.setContentMessageType(ProtocolMessageType.HANDSHAKE);
        r.setProtocolMessageBytes(Modifiable.explicit(new byte[0]));
        r.setMaxRecordLengthConfig(0);
        SendAction fin = new SendAction(new FinishedMessage());
        fin.setConfiguredRecords(List.of(r));

        WorkflowTrace workflowTrace =
                runner.generateWorkflowTraceUntilSendingMessage(
                        WorkflowTraceType.HANDSHAKE, HandshakeMessageType.FINISHED);
        workflowTrace.addTlsActions(fin, new ReceiveAction(new AlertMessage()));

        State state = runner.execute(workflowTrace, c);
        Validator.receivedFatalAlert(state, testCase);
    }

    @AnvilTest(id = "5246-oqJiBwUXN8")
    @ModelFromScope(modelType = "CERTIFICATE")
    @ExcludeParameter("RECORD_LENGTH")
    public void sendRecordWithPlaintextOver2pow14(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);

        ApplicationMessage msg = new ApplicationMessage();
        msg.setData(Modifiable.explicit(new byte[(int) (Math.pow(2, 14)) + 1]));

        Record overflowRecord = new Record();
        overflowRecord.setCleanProtocolMessageBytes(
                Modifiable.explicit(new byte[(int) (Math.pow(2, 14)) + 1]));
        // add dummy Application Message
        SendAction sendOverflow = new SendAction(new ApplicationMessage());
        sendOverflow.setConfiguredRecords(List.of(overflowRecord));

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        workflowTrace.addTlsActions(
                new ChangeConnectionTimeoutAction(
                        context.getConfig().getAnvilTestConfig().getConnectionTimeout() * 3),
                sendOverflow,
                new ReceiveAction(new AlertMessage()));

        State state = runner.execute(workflowTrace, c);

        Validator.receivedFatalAlert(state, testCase);
        AlertMessage alert = state.getWorkflowTrace().getFirstReceivedMessage(AlertMessage.class);
        Validator.testAlertDescription(state, testCase, AlertDescription.RECORD_OVERFLOW, alert);
    }

    @AnvilTest(id = "5246-6w2UjD5RGT")
    @ExcludeParameter("RECORD_LENGTH")
    public void sendRecordWithCiphertextOver2pow14plus2048(
            AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);

        Record overflowRecord = new Record();
        overflowRecord.setProtocolMessageBytes(
                Modifiable.explicit(new byte[(int) (Math.pow(2, 14)) + 2049]));
        // add dummy Application Message
        SendAction sendOverflow = new SendAction(new ApplicationMessage());
        sendOverflow.setConfiguredRecords(List.of(overflowRecord));

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        workflowTrace.addTlsActions(
                new ChangeConnectionTimeoutAction(
                        context.getConfig().getAnvilTestConfig().getConnectionTimeout() * 2),
                sendOverflow,
                new ReceiveAction(new AlertMessage()));

        State state = runner.execute(workflowTrace, c);
        Validator.executedAsPlanned(state, testCase);
        Validator.receivedFatalAlert(state, testCase);
        AlertMessage alert = state.getWorkflowTrace().getFirstReceivedMessage(AlertMessage.class);
        Validator.testAlertDescription(state, testCase, AlertDescription.RECORD_OVERFLOW, alert);
    }

    @NonCombinatorialAnvilTest(id = "5246-M5X6WTePcK")
    public void recordFragmentationSupported() {
        if (context.getConfig().isUseDTLS()) {
            assertTrue(
                    context.getFeatureExtractionResult()
                                    .getResult(TlsAnalyzedProperty.SUPPORTS_DTLS_FRAGMENTATION)
                            == TestResults.TRUE,
                    "DTLS record fragmentation support has not been detected");
        } else {
            assertTrue(
                    context.getFeatureExtractionResult()
                                    .getResult(TlsAnalyzedProperty.SUPPORTS_RECORD_FRAGMENTATION)
                            == TestResults.TRUE,
                    "Record fragmentation support has not been detected");
        }
    }
}
