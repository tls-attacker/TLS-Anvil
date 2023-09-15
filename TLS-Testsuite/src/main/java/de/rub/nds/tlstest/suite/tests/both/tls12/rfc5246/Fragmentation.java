/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.both.tls12.rfc5246;

import static org.junit.Assert.*;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.ExcludeParameter;
import de.rub.nds.anvilcore.coffee4j.model.ModelFromScope;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.record.Record;
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
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

public class Fragmentation extends Tls12Test {

    @AnvilTest
    @EnforcedSenderRestriction
    public void sendZeroLengthRecord_CCS(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        c.setUseAllProvidedRecords(true);

        Record r = new Record();
        r.setContentMessageType(ProtocolMessageType.CHANGE_CIPHER_SPEC);
        r.setMaxRecordLengthConfig(0);
        SendAction sendAction = new SendAction(new ChangeCipherSpecMessage());
        sendAction.setRecords(r);

        WorkflowTrace workflowTrace =
                runner.generateWorkflowTraceUntilSendingMessage(
                        WorkflowTraceType.HANDSHAKE, ProtocolMessageType.CHANGE_CIPHER_SPEC);
        workflowTrace.addTlsActions(
                sendAction,
                new SendAction(ActionOption.MAY_FAIL, new FinishedMessage()),
                new ReceiveAction(new AlertMessage()));

        runner.execute(workflowTrace, c).validateFinal(Validator::receivedFatalAlert);
    }

    @AnvilTest
    public void sendZeroLengthApplicationRecord(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        ApplicationMessage appMsg = new ApplicationMessage();

        Record r = new Record();
        r.setContentMessageType(ProtocolMessageType.APPLICATION_DATA);
        r.setMaxRecordLengthConfig(0);
        SendAction sendAction = new SendAction(appMsg);
        sendAction.setRecords(r);

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

        runner.execute(workflowTrace, c)
                .validateFinal(
                        i -> {
                            WorkflowTrace trace = i.getWorkflowTrace();
                            assertTrue(AssertMsgs.WORKFLOW_NOT_EXECUTED, trace.executedAsPlanned());

                            AlertMessage msg = trace.getFirstReceivedMessage(AlertMessage.class);
                            i.addAdditionalResultInfo("Evaluated with timeout " + reducedTimeout);
                            if (context.getFeatureExtractionResult().getClosedAfterAppDataDelta()
                                    > 0) {
                                assertNull("Received alert message", msg);
                                assertFalse("Socket was closed", Validator.socketClosed(i));
                            } else {
                                if (msg != null) {
                                    assertEquals(
                                            "SUT sent an alert that was not a Close Notify",
                                            AlertDescription.CLOSE_NOTIFY.getValue(),
                                            (byte) msg.getDescription().getValue());
                                }
                            }
                        });
    }

    @AnvilTest
    @ModelFromScope(modelType = "CERTIFICATE")
    @Tag("emptyRecord")
    public void sendEmptyApplicationRecord(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        ApplicationMessage appMsg = new ApplicationMessage();

        Record r = new Record();
        r.setContentMessageType(ProtocolMessageType.APPLICATION_DATA);
        r.setMaxRecordLengthConfig(0);
        r.setProtocolMessageBytes(Modifiable.explicit(new byte[0]));
        SendAction sendAction = new SendAction(appMsg);
        sendAction.setRecords(r);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        workflowTrace.addTlsActions(sendAction, new ReceiveAction(new AlertMessage()));

        runner.execute(workflowTrace, c).validateFinal(Validator::receivedFatalAlert);
    }

    @AnvilTest
    @Tag("emptyRecord")
    public void sendEmptyFinishedRecord(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        Record r = new Record();
        r.setContentMessageType(ProtocolMessageType.HANDSHAKE);
        r.setProtocolMessageBytes(Modifiable.explicit(new byte[0]));
        r.setMaxRecordLengthConfig(0);
        SendAction fin = new SendAction(new FinishedMessage());
        fin.setRecords(r);

        WorkflowTrace workflowTrace =
                runner.generateWorkflowTraceUntilSendingMessage(
                        WorkflowTraceType.HANDSHAKE, HandshakeMessageType.FINISHED);
        workflowTrace.addTlsActions(fin, new ReceiveAction(new AlertMessage()));

        runner.execute(workflowTrace, c).validateFinal(Validator::receivedFatalAlert);
    }

    @AnvilTest
    @ModelFromScope(modelType = "CERTIFICATE")
    @ExcludeParameter("RECORD_LENGTH")
    public void sendRecordWithPlaintextOver2pow14(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        ApplicationMessage msg = new ApplicationMessage();
        msg.setData(Modifiable.explicit(new byte[(int) (Math.pow(2, 14)) + 1]));

        Record overflowRecord = new Record();
        overflowRecord.setCleanProtocolMessageBytes(
                Modifiable.explicit(new byte[(int) (Math.pow(2, 14)) + 1]));
        // add dummy Application Message
        SendAction sendOverflow = new SendAction(new ApplicationMessage());
        sendOverflow.setRecords(overflowRecord);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        workflowTrace.addTlsActions(
                new ChangeConnectionTimeoutAction(
                        context.getConfig().getAnvilTestConfig().getConnectionTimeout() * 3),
                sendOverflow,
                new ReceiveAction(new AlertMessage()));

        runner.execute(workflowTrace, c)
                .validateFinal(
                        i -> {
                            Validator.receivedFatalAlert(i);
                            AlertMessage alert =
                                    i.getWorkflowTrace()
                                            .getFirstReceivedMessage(AlertMessage.class);
                            Validator.testAlertDescription(
                                    i, AlertDescription.RECORD_OVERFLOW, alert);
                        });
    }

    @AnvilTest
    @ExcludeParameter("RECORD_LENGTH")
    public void sendRecordWithCiphertextOver2pow14plus2048(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        Record overflowRecord = new Record();
        overflowRecord.setProtocolMessageBytes(
                Modifiable.explicit(new byte[(int) (Math.pow(2, 14)) + 2049]));
        // add dummy Application Message
        SendAction sendOverflow = new SendAction(new ApplicationMessage());
        sendOverflow.setRecords(overflowRecord);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        workflowTrace.addTlsActions(
                new ChangeConnectionTimeoutAction(
                        context.getConfig().getAnvilTestConfig().getConnectionTimeout() * 2),
                sendOverflow,
                new ReceiveAction(new AlertMessage()));

        runner.execute(workflowTrace, c)
                .validateFinal(
                        i -> {
                            Validator.receivedFatalAlert(i);
                            AlertMessage alert =
                                    i.getWorkflowTrace()
                                            .getFirstReceivedMessage(AlertMessage.class);
                            Validator.testAlertDescription(
                                    i, AlertDescription.RECORD_OVERFLOW, alert);
                        });
    }

    @Test
    public void recordFragmentationSupported() {
        assertTrue(
                "Record fragmentation support has not been detected",
                context.getFeatureExtractionResult()
                                .getResult(TlsAnalyzedProperty.SUPPORTS_RECORD_FRAGMENTATION)
                        == TestResults.TRUE);
    }
}
