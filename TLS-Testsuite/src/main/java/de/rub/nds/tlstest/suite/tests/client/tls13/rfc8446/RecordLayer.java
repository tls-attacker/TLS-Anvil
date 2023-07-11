/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.client.tls13.rfc8446;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.ExcludeParameter;
import de.rub.nds.anvilcore.annotation.ExplicitValues;
import de.rub.nds.anvilcore.annotation.IncludeParameter;
import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
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
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.ClientTest;
import de.rub.nds.tlstest.framework.annotations.EnforcedSenderRestriction;
import de.rub.nds.tlstest.framework.annotations.ManualConfig;
import de.rub.nds.tlstest.framework.annotations.MethodCondition;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.categories.AlertCategory;
import de.rub.nds.tlstest.framework.annotations.categories.ComplianceCategory;
import de.rub.nds.tlstest.framework.annotations.categories.RecordLayerCategory;
import de.rub.nds.tlstest.framework.annotations.categories.SecurityCategory;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.TlsParameterType;
import de.rub.nds.tlstest.framework.model.derivationParameter.AlertDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.ChosenHandshakeMessageDerivation;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
import java.util.LinkedList;
import java.util.List;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@ClientTest
@RFC(number = 8446, section = "5.1. Record Layer")
public class RecordLayer extends Tls13Test {

    @AnvilTest(
            description =
                    "Implementations MUST NOT send "
                            + "zero-length fragments of Handshake types, even "
                            + "if those fragments contain padding.")
    @RecordLayerCategory(SeverityLevel.LOW)
    @ComplianceCategory(SeverityLevel.HIGH)
    @AlertCategory(SeverityLevel.LOW)
    @EnforcedSenderRestriction
    public void zeroLengthRecord_ServerHello(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        c.setUseAllProvidedRecords(true);

        Record record = new Record();
        record.setMaxRecordLengthConfig(0);

        WorkflowTrace trace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        trace.addTlsActions(new ReceiveAction(new AlertMessage()));

        WorkflowTraceMutator.deleteSendingMessage(trace, HandshakeMessageType.SERVER_HELLO);
        SendAction serverHello = new SendAction(new ServerHelloMessage(c));
        serverHello.setRecords(record);
        trace.addTlsAction(1, serverHello);
        ((SendAction) trace.getTlsActions().get(2)).addActionOption(ActionOption.MAY_FAIL);

        runner.execute(trace, c).validateFinal(Validator::receivedFatalAlert);
    }

    @AnvilTest(
            description =
                    "Implementations "
                            + "MUST NOT send Handshake and Alert records that have a zero-length "
                            + "TLSInnerPlaintext.content; if such a message is received, the "
                            + "receiving implementation MUST terminate the connection with an "
                            + "\"unexpected_message\" alert.")
    @RFC(number = 8446, section = "5.4. Record Padding")
    @RecordLayerCategory(SeverityLevel.LOW)
    @ComplianceCategory(SeverityLevel.HIGH)
    @AlertCategory(SeverityLevel.LOW)
    public void zeroLengthRecord_Finished(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        c.setUseAllProvidedRecords(true);

        Record record = new Record();
        record.setMaxRecordLengthConfig(0);

        WorkflowTrace trace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        trace.addTlsActions(new ReceiveAction(new AlertMessage()));

        WorkflowTraceMutator.deleteSendingMessage(trace, HandshakeMessageType.FINISHED);
        SendAction finished = new SendAction(new FinishedMessage());
        finished.setRecords(record);
        trace.addTlsAction(2, finished);

        runner.execute(trace, c).validateFinal(Validator::receivedFatalAlert);
    }

    public ConditionEvaluationResult supportsRecordFragmentation() {
        if (context.getFeatureExtractionResult()
                        .getResult(TlsAnalyzedProperty.SUPPORTS_RECORD_FRAGMENTATION)
                == TestResults.TRUE) {
            return ConditionEvaluationResult.enabled("");
        }
        return ConditionEvaluationResult.disabled("Target does not support Record fragmentation");
    }

    @AnvilTest(
            description =
                    "Handshake messages MUST NOT be interleaved "
                            + "with other record types. That is, if a handshake message is split over two or more "
                            + "records, there MUST NOT be any other records between them.")
    @ExcludeParameter("RECORD_LENGTH")
    @IncludeParameter("ALERT")
    @RecordLayerCategory(SeverityLevel.LOW)
    @AlertCategory(SeverityLevel.LOW)
    @ComplianceCategory(SeverityLevel.HIGH)
    @MethodCondition(method = "supportsRecordFragmentation")
    @EnforcedSenderRestriction
    public void interleaveRecords(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace trace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        SendAction sendServerHelloAction =
                (SendAction)
                        WorkflowTraceUtil.getFirstSendingActionForMessage(
                                HandshakeMessageType.SERVER_HELLO, trace);
        AlertDescription selectedAlert =
                parameterCombination.getParameter(AlertDerivation.class).getSelectedValue();

        Record unmodifiedServerHelloRecord = new Record();
        Record unmodifiedEncryptedExtensionsRecord = new Record();
        Record certificateRecordFragment = new Record();
        certificateRecordFragment.setMaxRecordLengthConfig(20);
        Record alertRecord = new Record();

        // we add a record that will remain untouched by record layer but has
        // an alert set as explicit content
        alertRecord.setMaxRecordLengthConfig(0);
        alertRecord.setContentType(Modifiable.explicit(ProtocolMessageType.ALERT.getValue()));
        byte[] alertContent = new byte[] {AlertLevel.WARNING.getValue(), selectedAlert.getValue()};
        alertRecord.setProtocolMessageBytes(Modifiable.explicit(alertContent));

        sendServerHelloAction.setRecords(
                unmodifiedServerHelloRecord,
                unmodifiedEncryptedExtensionsRecord,
                certificateRecordFragment,
                alertRecord);

        trace.addTlsAction(new ReceiveAction(new AlertMessage()));

        runner.execute(trace, c).validateFinal(Validator::receivedFatalAlert);
    }

    public List<DerivationParameter> getModifiableHandshakeMessages(DerivationScope scope) {
        List<DerivationParameter> parameterValues = new LinkedList<>();
        parameterValues.add(
                new ChosenHandshakeMessageDerivation(HandshakeMessageType.ENCRYPTED_EXTENSIONS));
        parameterValues.add(new ChosenHandshakeMessageDerivation(HandshakeMessageType.CERTIFICATE));
        parameterValues.add(
                new ChosenHandshakeMessageDerivation(HandshakeMessageType.CERTIFICATE_VERIFY));

        return parameterValues;
    }

    @AnvilTest(description = "Send a record without any content to increase the sequencenumber.")
    @IncludeParameter("CHOSEN_HANDSHAKE_MSG")
    @ExcludeParameter("RECORD_LENGTH")
    @ExplicitValues(
            affectedIdentifiers = "CHOSEN_HANDSHAKE_MSG",
            methods = "getModifiableHandshakeMessages")
    @ManualConfig(TlsParameterType.CHOSEN_HANDSHAKE_MSG)
    @Tag("emptyRecord")
    @RecordLayerCategory(SeverityLevel.CRITICAL)
    @SecurityCategory(SeverityLevel.CRITICAL)
    @ComplianceCategory(SeverityLevel.HIGH)
    @AlertCategory(SeverityLevel.LOW)
    public void sendEmptyZeroLengthRecords(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        HandshakeMessageType affectedMessage =
                parameterCombination
                        .getParameter(ChosenHandshakeMessageDerivation.class)
                        .getSelectedValue();

        Record r = new Record();
        r.setContentMessageType(ProtocolMessageType.HANDSHAKE);
        r.setProtocolMessageBytes(Modifiable.explicit(new byte[0]));
        r.setMaxRecordLengthConfig(0);

        WorkflowTrace trace = new WorkflowTrace();
        SendAction action;
        if (affectedMessage == HandshakeMessageType.ENCRYPTED_EXTENSIONS) {
            trace =
                    runner.generateWorkflowTraceUntilSendingMessage(
                            WorkflowTraceType.HANDSHAKE, HandshakeMessageType.ENCRYPTED_EXTENSIONS);
            action =
                    new SendAction(
                            new EncryptedExtensionsMessage(),
                            new CertificateMessage(),
                            new CertificateVerifyMessage());
            action.setRecords(r);
            trace.addTlsActions(action, new ReceiveAction(new AlertMessage()));
        } else if (affectedMessage == HandshakeMessageType.CERTIFICATE) {
            trace =
                    runner.generateWorkflowTraceUntilSendingMessage(
                            WorkflowTraceType.HANDSHAKE, HandshakeMessageType.CERTIFICATE);
            action = new SendAction(new CertificateMessage(), new CertificateVerifyMessage());
            action.setRecords(r);
            trace.addTlsActions(action, new ReceiveAction(new AlertMessage()));
        } else if (affectedMessage == HandshakeMessageType.CERTIFICATE_VERIFY) {
            trace =
                    runner.generateWorkflowTraceUntilSendingMessage(
                            WorkflowTraceType.HANDSHAKE, HandshakeMessageType.CERTIFICATE_VERIFY);
            action = new SendAction(new CertificateVerifyMessage());
            action.setRecords(r);
            trace.addTlsActions(action, new ReceiveAction(new AlertMessage()));
        }
        runner.execute(trace, c).validateFinal(Validator::receivedFatalAlert);
    }

    @AnvilTest(
            description =
                    "Handshake messages MUST NOT span key changes. Implementations "
                            + "MUST verify that all messages immediately preceding a key change "
                            + "align with a record boundary; if not, then they MUST terminate the "
                            + "connection with an \"unexpected_message\" alert.")
    @ExcludeParameter("RECORD_LENGTH")
    @RecordLayerCategory(SeverityLevel.HIGH)
    @ComplianceCategory(SeverityLevel.HIGH)
    @Tag("new")
    public void incompleteCertVerifyBeforeFinished(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace workflowTrace =
                runner.generateWorkflowTraceUntilLastSendingMessage(
                        WorkflowTraceType.HELLO, HandshakeMessageType.CERTIFICATE_VERIFY);
        SendAction sendCertVerifyPart = new SendAction(new CertificateVerifyMessage());

        Record certVerifyPart = new Record();
        certVerifyPart.setMaxRecordLengthConfig(15);
        // this record will take the remaining bytes but they won't be written
        // to the wire
        Record dummyRecord = new Record();
        dummyRecord.setCompleteRecordBytes(Modifiable.explicit(new byte[0]));
        sendCertVerifyPart.setRecords(certVerifyPart, dummyRecord);

        workflowTrace.addTlsActions(sendCertVerifyPart, new SendAction(new FinishedMessage()));
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));

        runner.execute(workflowTrace, config)
                .validateFinal(
                        i -> {
                            Validator.receivedFatalAlert(i);
                            // Depending on the parsing behavior, this might yield a different
                            // alert
                            // Validator.testAlertDescription(i,
                            // AlertDescription.UNEXPECTED_MESSAGE);
                        });
    }
}
