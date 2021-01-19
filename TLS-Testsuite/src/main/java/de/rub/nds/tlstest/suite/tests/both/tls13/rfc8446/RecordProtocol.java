/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.both.tls13.rfc8446;

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
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.GenericReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.ScopeExtensions;
import de.rub.nds.tlstest.framework.annotations.ScopeLimitations;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.annotations.categories.Alert;
import de.rub.nds.tlstest.framework.annotations.categories.Compliance;
import de.rub.nds.tlstest.framework.annotations.categories.Interoperability;
import de.rub.nds.tlstest.framework.annotations.categories.RecordLayer;
import de.rub.nds.tlstest.framework.annotations.categories.Security;
import de.rub.nds.tlstest.framework.coffee4j.model.ModelFromScope;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.constants.TestEndpointType;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.DerivationType;
import de.rub.nds.tlstest.framework.model.ModelType;
import de.rub.nds.tlstest.framework.model.derivationParameter.ProtocolMessageTypeDerivation;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
import static org.junit.Assert.assertFalse;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;
import de.rub.nds.tlstest.framework.annotations.categories.Crypto;

@RFC(number = 8446, section = "5. Record Protocol")
public class RecordProtocol extends Tls13Test {

    @TlsTest(description = "Implementations MUST NOT send record types not "
            + "defined in this document unless negotiated by some extension. "
            + "If a TLS implementation receives an unexpected record type, "
            + "it MUST terminate the connection with an \"unexpected_message\" alert.")
    @Interoperability(SeverityLevel.LOW)
    @RecordLayer(SeverityLevel.LOW)
    @Alert(SeverityLevel.LOW)
    @Compliance(SeverityLevel.LOW)
    public void invalidRecordContentType(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
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

        trace.getFirstAction(SendAction.class).setRecords(record);

        runner.execute(trace, c).validateFinal(i -> {
            Validator.receivedFatalAlert(i);

            AlertMessage alert = i.getWorkflowTrace().getFirstReceivedMessage(AlertMessage.class);
            if (alert == null) {
                return;
            }
            Validator.testAlertDescription(i, AlertDescription.UNEXPECTED_MESSAGE, alert);
        });
    }

    @TlsTest(description = "Implementations MUST NOT send record types not "
            + "defined in this document unless negotiated by some extension. "
            + "If a TLS implementation receives an unexpected record type, "
            + "it MUST terminate the connection with an \"unexpected_message\" alert.")
    @ModelFromScope(baseModel = ModelType.CERTIFICATE)
    @Interoperability(SeverityLevel.LOW)
    @RecordLayer(SeverityLevel.LOW)
    @Alert(SeverityLevel.LOW)
    @Compliance(SeverityLevel.LOW)
    public void invalidRecordContentTypeAfterEncryption(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        WorkflowTrace workflowTrace = runner.generateWorkflowTraceUntilSendingMessage(WorkflowTraceType.HANDSHAKE, HandshakeMessageType.FINISHED);
        Record record = new Record();
        record.setContentType(Modifiable.explicit((byte) 0xff));
        FinishedMessage finished = new FinishedMessage(c);
        SendAction sendFinished = new SendAction(finished);
        sendFinished.setRecords(record);
        workflowTrace.addTlsActions(
                sendFinished,
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(workflowTrace, c).validateFinal(i -> {
            Validator.receivedFatalAlert(i);

            AlertMessage alert = i.getWorkflowTrace().getFirstReceivedMessage(AlertMessage.class);
            if (alert == null) {
                return;
            }
            Validator.testAlertDescription(i, AlertDescription.UNEXPECTED_MESSAGE, alert);
        });
    }

    @TlsTest(description = "If the decryption fails, the receiver MUST "
            + "terminate the connection with a \"bad_record_mac\" alert.")
    @ModelFromScope(baseModel = ModelType.CERTIFICATE)
    @Security(SeverityLevel.CRITICAL)
    @ScopeExtensions(DerivationType.AUTH_TAG_BITMASK)
    @Crypto(SeverityLevel.CRITICAL)
    @RecordLayer(SeverityLevel.CRITICAL)
    @Alert(SeverityLevel.HIGH)
    @Compliance(SeverityLevel.MEDIUM)
    public void invalidAuthTag(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        byte[] modificationBitmask = derivationContainer.buildBitmask();

        Record record = new Record();
        record.setComputations(new RecordCryptoComputations());
        record.getComputations().setAuthenticationTag(Modifiable.xor(modificationBitmask, 0));

        SendAction appData = new SendAction(new ApplicationMessage());
        appData.setRecords(record);
        WorkflowTrace trace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        trace.addTlsActions(
                appData,
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(trace, c).validateFinal(Validator::receivedFatalAlert);
    }

    @TlsTest(description = "The length (in bytes) of the following "
            + "TLSPlaintext.fragment.  The length MUST NOT exceed 2^14 bytes.  An "
            + "endpoint that receives a record that exceeds this length MUST "
            + "terminate the connection with a \"record_overflow\" alert.")
    @ModelFromScope(baseModel = ModelType.CERTIFICATE)
    @Interoperability(SeverityLevel.HIGH)
    @RFC(number = 8446, section = "5.1. Record Layer")
    @ScopeLimitations(DerivationType.RECORD_LENGTH)
    @RecordLayer(SeverityLevel.HIGH)
    @Compliance(SeverityLevel.HIGH)
    @Alert(SeverityLevel.LOW)
    public void sendRecordWithPlaintextOver2pow14(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        c.getDefaultClientConnection().setTimeout(5000);
        c.getDefaultServerConnection().setTimeout(5000);

        ApplicationMessage msg = new ApplicationMessage(c);
        Record overflowRecord = new Record();
        overflowRecord.setCleanProtocolMessageBytes(Modifiable.explicit(new byte[(int) (Math.pow(2, 14)) + 1]));
        SendAction sendOverflow = new SendAction(msg);
        sendOverflow.setRecords(overflowRecord);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        workflowTrace.addTlsActions(
                sendOverflow,
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(workflowTrace, c).validateFinal(i -> {
            Validator.receivedFatalAlert(i);
            AlertMessage alert = i.getWorkflowTrace().getFirstReceivedMessage(AlertMessage.class);
            if (alert == null) {
                return;
            }
            Validator.testAlertDescription(i, AlertDescription.RECORD_OVERFLOW, alert);
        });
    }

    @TlsTest(description = "If the decryption fails, the receiver MUST "
            + "terminate the connection with a \"bad_record_mac\" alert.")
    @ModelFromScope(baseModel = ModelType.CERTIFICATE)
    @Security(SeverityLevel.CRITICAL)
    @ScopeExtensions({DerivationType.CIPHERTEXT_BITMASK, DerivationType.APP_MSG_LENGHT})
    @RFC(number = 8446, section = "5.2. Record Payload Protection")
    @Crypto(SeverityLevel.CRITICAL)
    @RecordLayer(SeverityLevel.CRITICAL)
    @Alert(SeverityLevel.HIGH)
    @Compliance(SeverityLevel.MEDIUM)
    public void invalidCiphertext(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        byte[] modificationBitmask = derivationContainer.buildBitmask();

        Record record = new Record();
        record.setComputations(new RecordCryptoComputations());
        record.getComputations().setCiphertext(Modifiable.xor(modificationBitmask, 0));

        SendAction appData = new SendAction(new ApplicationMessage());
        appData.setRecords(record);
        WorkflowTrace trace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        trace.addTlsActions(
                appData,
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(trace, c).validateFinal(Validator::receivedFatalAlert);
    }

    @TlsTest(description = "All encrypted TLS records can be padded to inflate the size of the "
            + "TLSCiphertext.")
    @ModelFromScope(baseModel = ModelType.CERTIFICATE)
    @ScopeExtensions(DerivationType.ADDITIONAL_PADDING_LENGTH)
    @Interoperability(SeverityLevel.HIGH)
    @RecordLayer(SeverityLevel.CRITICAL)
    @Compliance(SeverityLevel.HIGH)
    public void acceptsOptionalPadding(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);

        runner.execute(workflowTrace, c).validateFinal(i -> {
            Validator.executedAsPlanned(i);
        });
    }

    @TlsTest(description = "The length MUST NOT exceed 2^14 + 256 bytes. "
            + "An endpoint that receives a record that exceeds this "
            + "length MUST terminate the connection with a \"record_overflow\" alert.")
    @ModelFromScope(baseModel = ModelType.CERTIFICATE)
    @Interoperability(SeverityLevel.HIGH)
    @ScopeLimitations(DerivationType.RECORD_LENGTH)
    @RFC(number = 8446, section = "5.2. Record Payload Protection")
    @RecordLayer(SeverityLevel.HIGH)
    @Compliance(SeverityLevel.HIGH)
    @Alert(SeverityLevel.LOW)
    public void sendRecordWithCiphertextOver2pow14plus256(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        c.getDefaultClientConnection().setTimeout(5000);
        c.getDefaultServerConnection().setTimeout(5000);

        Record overflowRecord = new Record();
        overflowRecord.setProtocolMessageBytes(Modifiable.explicit(new byte[(int) (Math.pow(2, 14)) + 257]));
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
            if (alert == null) {
                return;
            }
            Validator.testAlertDescription(i, AlertDescription.RECORD_OVERFLOW, alert);
        });
    }

    @TlsTest(description = "Send a record without any content.")
    @Security(SeverityLevel.CRITICAL)
    @Interoperability(SeverityLevel.HIGH)
    @Tag("emptyRecord")
    /*TODO: MM maybe we should make this a state machine tests?
    Also: does the content type do anything here? record type should be APP
    does the 'encoded' record type ignore MaxRecordLengthConfig?*/
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

    @TlsTest(description = "Send a record without any content.")
    @ModelFromScope(baseModel = ModelType.CERTIFICATE)
    @Security(SeverityLevel.CRITICAL)
    @Interoperability(SeverityLevel.HIGH)
    @ScopeExtensions(DerivationType.PROTOCOL_MESSAGE_TYPE)
    @Tag("emptyRecord")
    public void sendEmptyRecord(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        ProtocolMessageType selectedRecordContentType = derivationContainer.getDerivation(ProtocolMessageTypeDerivation.class).getSelectedValue();
        ApplicationMessage appMsg = new ApplicationMessage(c);

        Record r = new Record();
        r.setContentType(Modifiable.explicit(selectedRecordContentType.getValue()));
        r.setProtocolMessageBytes(Modifiable.explicit(new byte[0]));
        r.setMaxRecordLengthConfig(0);
        SendAction sendAction = new SendAction(appMsg);
        sendAction.setRecords(r);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        workflowTrace.addTlsActions(
                sendAction,
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(workflowTrace, c).validateFinal(Validator::receivedFatalAlert);
    }

    @TlsTest(description = "Zero-length"
            + "fragments of Application Data MAY be sent, as they are potentially "
            + "useful as a traffic analysis countermeasure.")
    @ModelFromScope(baseModel = ModelType.CERTIFICATE)
    @Security(SeverityLevel.CRITICAL)
    @Interoperability(SeverityLevel.HIGH)
    public void sendEmptyApplicationMessage(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        ApplicationMessage appMsg = new ApplicationMessage(c);
        appMsg.setData(Modifiable.explicit(new byte[0]));

        Record r = new Record();
        SendAction sendAction = new SendAction(appMsg);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        workflowTrace.addTlsActions(
                sendAction,
                new GenericReceiveAction()
        );

        runner.execute(workflowTrace, c).validateFinal(state -> {
            Validator.executedAsPlanned(state);
            assertFalse("Target did not accept an Application Data message without content", WorkflowTraceUtil.didReceiveMessage(ProtocolMessageType.ALERT, state.getWorkflowTrace()));
        });
    }

}
