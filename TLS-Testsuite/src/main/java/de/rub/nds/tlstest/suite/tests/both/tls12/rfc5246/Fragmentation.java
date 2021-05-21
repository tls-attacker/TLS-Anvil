/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.both.tls12.rfc5246;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CipherType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.GenericReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.ScopeLimitations;
import de.rub.nds.tlstest.framework.annotations.TestDescription;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.annotations.categories.AlertCategory;
import de.rub.nds.tlstest.framework.annotations.categories.ComplianceCategory;
import de.rub.nds.tlstest.framework.annotations.categories.HandshakeCategory;
import de.rub.nds.tlstest.framework.annotations.categories.InteroperabilityCategory;
import de.rub.nds.tlstest.framework.annotations.categories.RecordLayerCategory;
import de.rub.nds.tlstest.framework.annotations.categories.SecurityCategory;
import de.rub.nds.tlstest.framework.coffee4j.model.ModelFromScope;
import de.rub.nds.tlstest.framework.constants.AssertMsgs;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.DerivationType;
import de.rub.nds.tlstest.framework.model.ModelType;
import de.rub.nds.tlstest.framework.model.derivationParameter.CipherSuiteDerivation;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import org.junit.jupiter.api.Tag;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;
import org.junit.jupiter.api.Test;

@RFC(number = 5246, section = "6.2.1 Fragmentation")
public class Fragmentation extends Tls12Test {
    
    @TlsTest(description = "Implementations MUST NOT send zero-length fragments of Handshake, "
            + "Alert, or ChangeCipherSpec content types. Zero-length fragments of "
            + "Application data MAY be sent as they are potentially useful as a "
            + "traffic analysis countermeasure.")
    @RecordLayerCategory(SeverityLevel.HIGH)
    @ComplianceCategory(SeverityLevel.HIGH)
    @AlertCategory(SeverityLevel.LOW)
    public void sendZeroLengthRecord_CCS(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        c.setUseAllProvidedRecords(true);

        Record r = new Record();
        r.setContentMessageType(ProtocolMessageType.CHANGE_CIPHER_SPEC);
        r.setMaxRecordLengthConfig(0);
        SendAction sendAction = new SendAction(new ChangeCipherSpecMessage(c));
        sendAction.setRecords(r);

        WorkflowTrace workflowTrace = runner.generateWorkflowTraceUntilSendingMessage(WorkflowTraceType.HANDSHAKE, ProtocolMessageType.CHANGE_CIPHER_SPEC);
        workflowTrace.addTlsActions(
                sendAction,
                new SendAction(ActionOption.MAY_FAIL, new FinishedMessage()),
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(workflowTrace, c).validateFinal(Validator::receivedFatalAlert);
    }

    @TlsTest(description = "Implementations MUST NOT send zero-length fragments of Handshake, "
            + "Alert, or ChangeCipherSpec content types. Zero-length fragments of "
            + "Application data MAY be sent as they are potentially useful as a "
            + "traffic analysis countermeasure.")
    @RecordLayerCategory(SeverityLevel.HIGH)
    @ComplianceCategory(SeverityLevel.CRITICAL)
    public void sendZeroLengthApplicationRecord(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        ApplicationMessage appMsg = new ApplicationMessage(c);

        Record r = new Record();
        r.setContentMessageType(ProtocolMessageType.APPLICATION_DATA);
        r.setMaxRecordLengthConfig(0);
        SendAction sendAction = new SendAction(appMsg);
        sendAction.setRecords(r);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        workflowTrace.addTlsActions(
                sendAction,
                new GenericReceiveAction()
        );

        runner.execute(workflowTrace, c).validateFinal(i -> {
            WorkflowTrace trace = i.getWorkflowTrace();
            assertTrue(AssertMsgs.WorkflowNotExecuted, trace.executedAsPlanned());

            AlertMessage msg = trace.getFirstReceivedMessage(AlertMessage.class);
            assertNull("Received alert message", msg);
            assertFalse("Socket was closed", Validator.socketClosed(i));
        });
    }

    @TlsTest(description = "Send a record without any content with Content Type Application Data.")
    @ModelFromScope(baseModel = ModelType.CERTIFICATE)
    @Tag("emptyRecord")
    @RecordLayerCategory(SeverityLevel.CRITICAL)
    @SecurityCategory(SeverityLevel.CRITICAL)
    @AlertCategory(SeverityLevel.LOW)
    public void sendEmptyApplicationRecord(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        ApplicationMessage appMsg = new ApplicationMessage(c);

        Record r = new Record();
        r.setContentMessageType(ProtocolMessageType.APPLICATION_DATA);
        r.setMaxRecordLengthConfig(0);
        r.setProtocolMessageBytes(Modifiable.explicit(new byte[0]));
        SendAction sendAction = new SendAction(appMsg);
        sendAction.setRecords(r);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        workflowTrace.addTlsActions(
                sendAction,
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(workflowTrace, c).validateFinal(Validator::receivedFatalAlert);
    }

    @TlsTest(description = "Send a record without any content with Content Type Handshake.")
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

        WorkflowTrace workflowTrace = runner.generateWorkflowTraceUntilSendingMessage(WorkflowTraceType.HANDSHAKE, HandshakeMessageType.FINISHED);
        workflowTrace.addTlsActions(
                fin,
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(workflowTrace, c).validateFinal(Validator::receivedFatalAlert);
    }

    @TlsTest(description = "The length (in bytes) of the following TLSPlaintext.fragment. "
            + "The length MUST NOT exceed 2^14.")
    @ModelFromScope(baseModel = ModelType.CERTIFICATE)
    @ScopeLimitations(DerivationType.RECORD_LENGTH)
    @RecordLayerCategory(SeverityLevel.HIGH)
    @ComplianceCategory(SeverityLevel.HIGH)
    @AlertCategory(SeverityLevel.MEDIUM)
    public void sendRecordWithPlaintextOver2pow14(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        c.getDefaultClientConnection().setTimeout(2000);
        c.getDefaultServerConnection().setTimeout(2000);

        ApplicationMessage msg = new ApplicationMessage(c);
        msg.setData(Modifiable.explicit(new byte[(int) (Math.pow(2, 14)) + 1]));

        Record overflowRecord = new Record();
        overflowRecord.setCleanProtocolMessageBytes(Modifiable.explicit(new byte[(int) (Math.pow(2, 14)) + 1]));
        //add dummy Application Message
        SendAction sendOverflow = new SendAction(new ApplicationMessage(c));
        sendOverflow.setRecords(overflowRecord);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        workflowTrace.addTlsActions(
                sendOverflow,
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(workflowTrace, c).validateFinal(i -> {
            Validator.receivedFatalAlert(i);
            AlertMessage alert = i.getWorkflowTrace().getFirstReceivedMessage(AlertMessage.class);
            Validator.testAlertDescription(i, AlertDescription.RECORD_OVERFLOW, alert);
        });
    }

    @TlsTest(description = "The length (in bytes) of the following TLSCiphertext.fragment. "
            + "The length MUST NOT exceed 2^14 + 2048.")
    @ScopeLimitations(DerivationType.RECORD_LENGTH)
    @RecordLayerCategory(SeverityLevel.HIGH)
    @ComplianceCategory(SeverityLevel.HIGH)
    @AlertCategory(SeverityLevel.MEDIUM)
    public void sendRecordWithCiphertextOver2pow14plus2048(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        c.getDefaultClientConnection().setTimeout(2000);
        c.getDefaultServerConnection().setTimeout(2000);

        Record overflowRecord = new Record();
        overflowRecord.setProtocolMessageBytes(Modifiable.explicit(new byte[(int) (Math.pow(2, 14)) + 2049]));
        //add dummy Application Message
        SendAction sendOverflow = new SendAction(new ApplicationMessage(c));
        sendOverflow.setRecords(overflowRecord);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        workflowTrace.addTlsActions(
                sendOverflow,
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(workflowTrace, c).validateFinal(i -> {
            Validator.receivedFatalAlert(i);
            AlertMessage alert = i.getWorkflowTrace().getFirstReceivedMessage(AlertMessage.class);
            Validator.testAlertDescription(i, AlertDescription.RECORD_OVERFLOW, alert);
        });
    }
    
    @Test
    @TestDescription("Evaluate if the preparation phase detected that the target is able to process fragmented Records")
    @InteroperabilityCategory(SeverityLevel.HIGH)
    @RecordLayerCategory(SeverityLevel.HIGH)
    @ComplianceCategory(SeverityLevel.CRITICAL)
    @HandshakeCategory(SeverityLevel.HIGH)
    public void recordFragmentationSupported() {
        assertTrue("Record fragmentation support has not been detected", context.getSiteReport().getSupportsRecordFragmentation());
    }
}
