/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.both.tls12.rfc5246;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.DynamicValueConstraints;
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
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.ScopeLimitations;
import de.rub.nds.tlstest.framework.annotations.TestDescription;
import de.rub.nds.tlstest.framework.annotations.categories.AlertCategory;
import de.rub.nds.tlstest.framework.annotations.categories.ComplianceCategory;
import de.rub.nds.tlstest.framework.annotations.categories.HandshakeCategory;
import de.rub.nds.tlstest.framework.annotations.categories.InteroperabilityCategory;
import de.rub.nds.tlstest.framework.annotations.categories.RecordLayerCategory;
import de.rub.nds.tlstest.framework.annotations.categories.SecurityCategory;
import de.rub.nds.tlstest.framework.constants.AssertMsgs;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.TlsParameterType;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@RFC(number = 5246, section = "6.2.1 Fragmentation")
public class Fragmentation extends Tls12Test {

    @AnvilTest(
            description =
                    "Implementations MUST NOT send zero-length fragments of Handshake, "
                            + "Alert, or ChangeCipherSpec content types. Zero-length fragments of "
                            + "Application data MAY be sent as they are potentially useful as a "
                            + "traffic analysis countermeasure.")
    @RecordLayerCategory(SeverityLevel.HIGH)
    @ComplianceCategory(SeverityLevel.HIGH)
    @AlertCategory(SeverityLevel.LOW)
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

    @AnvilTest(
            description =
                    "Implementations MUST NOT send zero-length fragments of Handshake, "
                            + "Alert, or ChangeCipherSpec content types. Zero-length fragments of "
                            + "Application data MAY be sent as they are potentially useful as a "
                            + "traffic analysis countermeasure.")
    @RecordLayerCategory(SeverityLevel.HIGH)
    @ComplianceCategory(SeverityLevel.CRITICAL)
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
        int baseTimeout = context.getConfig().getConnectionTimeout();
        if (context.getFeatureExtractionResult().getClosedAfterAppDataDelta() > 0
                && context.getFeatureExtractionResult().getClosedAfterAppDataDelta()
                        < context.getConfig().getConnectionTimeout()) {
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
                            assertTrue(AssertMsgs.WorkflowNotExecuted, trace.executedAsPlanned());

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

    @AnvilTest(
            description =
                    "Send a record without any content with Content Type Application Data. "
                            + " The former record increases the sequencenumber, which should not be allowed")
    @ModelFromScope(modelType = "CERTIFICATE")
    @Tag("emptyRecord")
    @RecordLayerCategory(SeverityLevel.CRITICAL)
    @SecurityCategory(SeverityLevel.CRITICAL)
    @AlertCategory(SeverityLevel.LOW)
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

    @AnvilTest(
            description =
                    "Send a record without any content with Content Type Handshake followed by an encrypted record. "
                            + " The former record increases the sequencenumber, which should not be allowed")
    @SecurityCategory(SeverityLevel.CRITICAL)
    @ComplianceCategory(SeverityLevel.CRITICAL)
    @RecordLayerCategory(SeverityLevel.CRITICAL)
    @AlertCategory(SeverityLevel.LOW)
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

    @AnvilTest(
            description =
                    "The length (in bytes) of the following TLSPlaintext.fragment. "
                            + "The length MUST NOT exceed 2^14.")
    @ModelFromScope(modelType = "CERTIFICATE")
    @ScopeLimitations(TlsParameterType.RECORD_LENGTH)
    @RecordLayerCategory(SeverityLevel.HIGH)
    @ComplianceCategory(SeverityLevel.HIGH)
    @AlertCategory(SeverityLevel.MEDIUM)
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
                new ChangeConnectionTimeoutAction(context.getConfig().getConnectionTimeout() * 3),
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

    @AnvilTest(
            description =
                    "The length (in bytes) of the following TLSCiphertext.fragment. "
                            + "The length MUST NOT exceed 2^14 + 2048") // .
    @ScopeLimitations(TlsParameterType.RECORD_LENGTH)
    @RecordLayerCategory(SeverityLevel.HIGH)
    @ComplianceCategory(SeverityLevel.HIGH)
    @AlertCategory(SeverityLevel.MEDIUM)
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
                new ChangeConnectionTimeoutAction(context.getConfig().getConnectionTimeout() * 2),
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
    @TestDescription(
            "Client "
                    + "message boundaries are not preserved in the record layer [...] "
                    + "a single message MAY be fragmented across several records")
    @InteroperabilityCategory(SeverityLevel.HIGH)
    @RecordLayerCategory(SeverityLevel.HIGH)
    @ComplianceCategory(SeverityLevel.CRITICAL)
    @HandshakeCategory(SeverityLevel.HIGH)
    public void recordFragmentationSupported() {
        assertTrue(
                "Record fragmentation support has not been detected",
                context.getFeatureExtractionResult()
                                .getResult(TlsAnalyzedProperty.SUPPORTS_RECORD_FRAGMENTATION)
                        == TestResults.TRUE);
    }
}
