/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.client.tls13.rfc8446;

import de.rub.nds.anvilcore.annotation.*;
import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.teststate.AnvilTestCase;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceMutator;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceResultUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.EnforcedSenderRestriction;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.derivationParameter.AlertDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.ChosenHandshakeMessageDerivation;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
import java.util.LinkedList;
import java.util.List;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;

@ClientTest
public class RecordLayer extends Tls13Test {

    @AnvilTest(id = "8446-i8hwrTotPM")
    @EnforcedSenderRestriction
    public void zeroLengthRecord_ServerHello(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);

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

        State state = runner.execute(trace, c);
        Validator.receivedFatalAlert(state, testCase);
    }

    @AnvilTest(id = "8446-2R6GNvoUEs")
    public void zeroLengthRecord_Finished(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);

        c.setUseAllProvidedRecords(true);

        Record record = new Record();
        record.setMaxRecordLengthConfig(0);

        WorkflowTrace trace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        trace.addTlsActions(new ReceiveAction(new AlertMessage()));

        WorkflowTraceMutator.deleteSendingMessage(trace, HandshakeMessageType.FINISHED);
        SendAction finished = new SendAction(new FinishedMessage());
        finished.setRecords(record);
        trace.addTlsAction(2, finished);

        State state = runner.execute(trace, c);
        Validator.receivedFatalAlert(state, testCase);
    }

    public ConditionEvaluationResult supportsRecordFragmentation() {
        if (context.getFeatureExtractionResult()
                        .getResult(TlsAnalyzedProperty.SUPPORTS_RECORD_FRAGMENTATION)
                == TestResults.TRUE) {
            return ConditionEvaluationResult.enabled("");
        }
        return ConditionEvaluationResult.disabled("Target does not support Record fragmentation");
    }

    @AnvilTest(id = "8446-BbKKCCtSdd")
    @ExcludeParameter("RECORD_LENGTH")
    @IncludeParameter("ALERT")
    @MethodCondition(method = "supportsRecordFragmentation")
    @EnforcedSenderRestriction
    public void interleaveRecords(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);
        WorkflowTrace trace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        SendAction sendServerHelloAction =
                (SendAction)
                        WorkflowTraceResultUtil.getFirstActionThatSent(
                                trace, HandshakeMessageType.SERVER_HELLO);
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

        State state = runner.execute(trace, c);
        Validator.receivedFatalAlert(state, testCase);
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

    @AnvilTest(id = "8446-m6iEnsoJCw")
    @IncludeParameter("CHOSEN_HANDSHAKE_MSG")
    @ExcludeParameter("RECORD_LENGTH")
    @ExplicitValues(
            affectedIdentifiers = "CHOSEN_HANDSHAKE_MSG",
            methods = "getModifiableHandshakeMessages")
    @ManualConfig(identifiers = "CHOSEN_HANDSHAKE_MSG")
    @Tag("emptyRecord")
    public void sendEmptyZeroLengthRecords(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);
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
        State state = runner.execute(trace, c);
        Validator.receivedFatalAlert(state, testCase);
    }

    @AnvilTest(id = "8446-VNQgpDNZVS")
    @ExcludeParameter("RECORD_LENGTH")
    @Tag("new")
    public void incompleteCertVerifyBeforeFinished(AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);
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

        State state = runner.execute(workflowTrace, config);
        Validator.receivedFatalAlert(state, testCase);
        // Depending on the parsing behavior, this might yield a different alert
        // Validator.testAlertDescription(state, testCase, AlertDescription.UNEXPECTED_MESSAGE);
    }
}
