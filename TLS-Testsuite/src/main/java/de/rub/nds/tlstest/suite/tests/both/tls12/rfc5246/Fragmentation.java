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
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.ScopeLimitations;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.annotations.categories.Interoperability;
import de.rub.nds.tlstest.framework.annotations.categories.Security;
import de.rub.nds.tlstest.framework.coffee4j.model.ModelFromScope;
import de.rub.nds.tlstest.framework.constants.AssertMsgs;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.DerivationType;
import de.rub.nds.tlstest.framework.model.ModelType;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import org.junit.jupiter.api.Tag;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@RFC(number = 5264, section = "6.2.1 Fragmentation")
public class Fragmentation extends Tls12Test {

    @TlsTest(description = "Implementations MUST NOT send zero-length fragments of Handshake, " +
            "Alert, or ChangeCipherSpec content types. Zero-length fragments of " +
            "Application data MAY be sent as they are potentially useful as a " +
            "traffic analysis countermeasure.")
    @Interoperability(SeverityLevel.HIGH)
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


    @TlsTest(description = "Implementations MUST NOT send zero-length fragments of Handshake, " +
            "Alert, or ChangeCipherSpec content types. Zero-length fragments of " +
            "Application data MAY be sent as they are potentially useful as a " +
            "traffic analysis countermeasure.")
    @Interoperability(SeverityLevel.HIGH)
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
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(workflowTrace, c).validateFinal(i -> {
            WorkflowTrace trace = i.getWorkflowTrace();
            assertFalse(AssertMsgs.WorkflowNotExecuted, trace.executedAsPlanned());

            AlertMessage msg = trace.getFirstReceivedMessage(AlertMessage.class);
            assertNull("Received alert message", msg);
        });
    }

    @TlsTest(description = "Send a record without any content.")
    @ModelFromScope(baseModel = ModelType.CERTIFICATE)
    @Tag("emptyRecord")
    @Security(SeverityLevel.CRITICAL)
    @Interoperability(SeverityLevel.HIGH)
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

    @TlsTest(description = "Send a record without any content.")
    @Security(SeverityLevel.CRITICAL)
    @Interoperability(SeverityLevel.HIGH)
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

    @TlsTest(description = "The length (in bytes) of the following TLSCiphertext.fragment. " +
            "The length MUST NOT exceed 2^14 + 2048.")
    @ModelFromScope(baseModel = ModelType.CERTIFICATE)
    @ScopeLimitations(DerivationType.RECORD_LENGTH)
    @Interoperability(SeverityLevel.HIGH)
    public void sendRecordWithPlaintextOver2pow14plus1(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        c.getDefaultClientConnection().setTimeout(5000);
        c.getDefaultServerConnection().setTimeout(5000);

        ApplicationMessage msg = new ApplicationMessage(c);
        msg.setData(Modifiable.explicit(new byte[(int) (Math.pow(2, 14)) + 1]));

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        workflowTrace.addTlsActions(
                new SendAction(msg),
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(workflowTrace, c).validateFinal(i -> {
            Validator.receivedFatalAlert(i);
            AlertMessage alert = i.getWorkflowTrace().getFirstReceivedMessage(AlertMessage.class);
            if (alert == null) return;
            Validator.testAlertDescription(i, AlertDescription.RECORD_OVERFLOW, alert);
        });
    }

    @TlsTest(description = "The length (in bytes) of the following TLSPlaintext.fragment. " +
            "The length MUST NOT exceed 2^14.")
    @ScopeLimitations(DerivationType.RECORD_LENGTH)
    @Interoperability(SeverityLevel.HIGH)
    public void sendRecordWithCiphertextOver2pow14plus1(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        c.getDefaultClientConnection().setTimeout(5000);
        c.getDefaultServerConnection().setTimeout(5000);

        ApplicationMessage msg = new ApplicationMessage(c);
        msg.setData(Modifiable.explicit(new byte[(int) (Math.pow(2, 14)) + 2049]));

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        workflowTrace.addTlsActions(
                new SendAction(msg),
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(workflowTrace, c).validateFinal(i -> {
            Validator.receivedFatalAlert(i);
            AlertMessage alert = i.getWorkflowTrace().getFirstReceivedMessage(AlertMessage.class);
            if (alert == null) return;
            Validator.testAlertDescription(i, AlertDescription.RECORD_OVERFLOW, alert);
        });
    }
}
