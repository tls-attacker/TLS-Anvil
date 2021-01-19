/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.client.tls13.rfc8446;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.core.protocol.message.EncryptedExtensionsMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceMutator;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.ClientTest;
import de.rub.nds.tlstest.framework.annotations.ExplicitValues;
import de.rub.nds.tlstest.framework.annotations.ManualConfig;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.ScopeExtensions;
import de.rub.nds.tlstest.framework.annotations.ScopeLimitations;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.annotations.categories.Alert;
import de.rub.nds.tlstest.framework.annotations.categories.Compliance;
import de.rub.nds.tlstest.framework.annotations.categories.Interoperability;
import de.rub.nds.tlstest.framework.annotations.categories.Security;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.DerivationType;
import de.rub.nds.tlstest.framework.model.derivationParameter.ChosenHandshakeMessageDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.DerivationParameter;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
import java.util.LinkedList;
import java.util.List;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@ClientTest
@RFC(number = 8446, section = "5.1. Record Layer")
public class RecordLayer extends Tls13Test {

    @TlsTest(description = "Implementations MUST NOT send "
            + "zero-length fragments of Handshake types, even "
            + "if those fragments contain padding.")
    @Interoperability(SeverityLevel.HIGH)
    @de.rub.nds.tlstest.framework.annotations.categories.RecordLayer(SeverityLevel.LOW)
    @Compliance(SeverityLevel.HIGH)
    public void zeroLengthRecord_ServerHello(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        c.setUseAllProvidedRecords(true);

        Record record = new Record();
        record.setMaxRecordLengthConfig(0);

        WorkflowTrace trace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        trace.addTlsActions(
                new ReceiveAction(new AlertMessage())
        );

        WorkflowTraceMutator.deleteSendingMessage(trace, HandshakeMessageType.SERVER_HELLO);
        SendAction serverHello = new SendAction(new ServerHelloMessage(c));
        serverHello.setRecords(record);
        trace.addTlsAction(1, serverHello);
        ((SendAction) trace.getTlsActions().get(2)).addActionOption(ActionOption.MAY_FAIL);

        runner.execute(trace, c).validateFinal(Validator::receivedFatalAlert);
    }

    @TlsTest(description = "Implementations MUST NOT send "
            + "zero-length fragments of Handshake types, even "
            + "if those fragments contain padding.")
    @Interoperability(SeverityLevel.HIGH)
    @de.rub.nds.tlstest.framework.annotations.categories.RecordLayer(SeverityLevel.LOW)
    @Compliance(SeverityLevel.HIGH)
    public void zeroLengthRecord_Finished(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        c.setUseAllProvidedRecords(true);

        Record record = new Record();
        record.setMaxRecordLengthConfig(0);

        WorkflowTrace trace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        trace.addTlsActions(
                new ReceiveAction(new AlertMessage())
        );

        WorkflowTraceMutator.deleteSendingMessage(trace, HandshakeMessageType.FINISHED);
        SendAction finished = new SendAction(new FinishedMessage(c));
        finished.setRecords(record);
        trace.addTlsAction(2, finished);

        runner.execute(trace, c).validateFinal(Validator::receivedFatalAlert);
    }

    @TlsTest(description = "Handshake messages MUST NOT be interleaved "
            + "with other record types.")
    @ScopeLimitations(DerivationType.INCLUDE_CHANGE_CIPHER_SPEC)
    @Interoperability(SeverityLevel.HIGH)
    @de.rub.nds.tlstest.framework.annotations.categories.RecordLayer(SeverityLevel.LOW)
    @Alert(SeverityLevel.LOW)
    @Compliance(SeverityLevel.HIGH)
    /*TODO: is this test correct? by my understanding it tests if two different
    record content type messages may be in the same record (with only 1 content
    type given in the header) - the RFC states right below the quote from above 
    "That is, if a handshake message is split over two or more records, there 
    MUST NOT be any other records between them.
    We aren't always fragmenting here so this description doesn't match.
    */
    public void interleaveRecords(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        c.setCreateIndividualRecords(false);
        c.setFlushOnMessageTypeChange(false);

        WorkflowTrace trace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        trace.addTlsAction(new ReceiveAction(new AlertMessage()));

        runner.execute(trace, c).validateFinal(Validator::receivedFatalAlert);
    }

    public List<DerivationParameter> getModifiableHandshakeMessages() {
        List<DerivationParameter> parameterValues = new LinkedList<>();
        parameterValues.add(new ChosenHandshakeMessageDerivation(HandshakeMessageType.ENCRYPTED_EXTENSIONS));
        parameterValues.add(new ChosenHandshakeMessageDerivation(HandshakeMessageType.CERTIFICATE));
        parameterValues.add(new ChosenHandshakeMessageDerivation(HandshakeMessageType.CERTIFICATE_VERIFY));

        return parameterValues;
    }

    @TlsTest(description = "Send a record without any content.")
    @ScopeExtensions(DerivationType.CHOSEN_HANDSHAKE_MSG)
    @ScopeLimitations(DerivationType.RECORD_LENGTH)
    @ExplicitValues(affectedTypes = DerivationType.CHOSEN_HANDSHAKE_MSG, methods = "getModifiableHandshakeMessages")
    @ManualConfig(DerivationType.CHOSEN_HANDSHAKE_MSG)
    @Tag("emptyRecord")
    @Interoperability(SeverityLevel.HIGH)
    @de.rub.nds.tlstest.framework.annotations.categories.RecordLayer(SeverityLevel.CRITICAL)
    @Security(SeverityLevel.CRITICAL)
    @Compliance(SeverityLevel.HIGH)
    public void sendEmptyZeroLengthRecords(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        HandshakeMessageType affectedMessage = derivationContainer.getDerivation(ChosenHandshakeMessageDerivation.class).getSelectedValue();

        Record r = new Record();
        r.setContentMessageType(ProtocolMessageType.HANDSHAKE);
        r.setProtocolMessageBytes(Modifiable.explicit(new byte[0]));
        r.setMaxRecordLengthConfig(0);

        WorkflowTrace trace = new WorkflowTrace();
        SendAction action;
        if (affectedMessage == HandshakeMessageType.ENCRYPTED_EXTENSIONS) {
            trace = runner.generateWorkflowTraceUntilSendingMessage(WorkflowTraceType.HANDSHAKE, HandshakeMessageType.ENCRYPTED_EXTENSIONS);
            action = new SendAction(new EncryptedExtensionsMessage(c), new CertificateMessage(c), new CertificateVerifyMessage(c));
            action.setRecords(r);
            trace.addTlsActions(action, new ReceiveAction(new AlertMessage()));
        } else if (affectedMessage == HandshakeMessageType.CERTIFICATE) {
            trace = runner.generateWorkflowTraceUntilSendingMessage(WorkflowTraceType.HANDSHAKE, HandshakeMessageType.CERTIFICATE);
            action = new SendAction(new CertificateMessage(c), new CertificateVerifyMessage(c));
            action.setRecords(r);
            trace.addTlsActions(action, new ReceiveAction(new AlertMessage()));
        } else if (affectedMessage == HandshakeMessageType.CERTIFICATE_VERIFY) {
            trace = runner.generateWorkflowTraceUntilSendingMessage(WorkflowTraceType.HANDSHAKE, HandshakeMessageType.CERTIFICATE_VERIFY);
            action = new SendAction(new CertificateVerifyMessage(c));
            action.setRecords(r);
            trace.addTlsActions(action, new ReceiveAction(new AlertMessage()));
        }
        runner.execute(trace, c).validateFinal(Validator::receivedFatalAlert);
    }
}
