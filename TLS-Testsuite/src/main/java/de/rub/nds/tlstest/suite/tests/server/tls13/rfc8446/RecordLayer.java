/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * Copyright 2022 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.server.tls13.rfc8446;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.RecordCryptoComputations;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceivingAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.EnforcedSenderRestriction;
import de.rub.nds.tlstest.framework.annotations.ExplicitValues;
import de.rub.nds.tlstest.framework.annotations.MethodCondition;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.ScopeExtensions;
import de.rub.nds.tlstest.framework.annotations.ScopeLimitations;
import de.rub.nds.tlstest.framework.annotations.ServerTest;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.annotations.categories.AlertCategory;
import de.rub.nds.tlstest.framework.annotations.categories.ComplianceCategory;
import de.rub.nds.tlstest.framework.annotations.categories.CryptoCategory;
import de.rub.nds.tlstest.framework.annotations.categories.DeprecatedFeatureCategory;
import de.rub.nds.tlstest.framework.annotations.categories.HandshakeCategory;
import de.rub.nds.tlstest.framework.annotations.categories.InteroperabilityCategory;
import de.rub.nds.tlstest.framework.annotations.categories.MessageStructureCategory;
import de.rub.nds.tlstest.framework.annotations.categories.RecordLayerCategory;
import de.rub.nds.tlstest.framework.annotations.categories.SecurityCategory;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.DerivationScope;
import de.rub.nds.tlstest.framework.model.DerivationType;
import de.rub.nds.tlstest.framework.model.derivationParameter.AlertDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.DerivationParameter;
import de.rub.nds.tlstest.framework.model.derivationParameter.ProtocolVersionDerivation;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
import java.util.LinkedList;
import java.util.List;
import static org.junit.Assert.assertArrayEquals;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@ServerTest
@RFC(number = 8446, section = "5.1. Record Layer")
public class RecordLayer extends Tls13Test {

    @TlsTest(description = "Implementations MUST NOT send "
            + "zero-length fragments of Handshake types, even "
            + "if those fragments contain padding.")
    @RecordLayerCategory(SeverityLevel.LOW)
    @ComplianceCategory(SeverityLevel.HIGH)
    @AlertCategory(SeverityLevel.LOW)
    @EnforcedSenderRestriction
    public void zeroLengthRecord_CH(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        c.setUseAllProvidedRecords(true);

        SendAction clientHello = new SendAction(new ClientHelloMessage(c));
        Record record = new Record();
        record.setMaxRecordLengthConfig(0);
        clientHello.setRecords(record);

        WorkflowTrace trace = new WorkflowTrace();
        trace.addTlsActions(
                clientHello,
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(trace, c).validateFinal(Validator::receivedFatalAlert);
    }

    @TlsTest(description = "Implementations " +
        "MUST NOT send Handshake and Alert records that have a zero-length " +
        "TLSInnerPlaintext.content; if such a message is received, the " +
        "receiving implementation MUST terminate the connection with an " +
        "\"unexpected_message\" alert.")
    @RFC(number = 8446, section = "5.4. Record Padding")
    @RecordLayerCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    @AlertCategory(SeverityLevel.LOW)
    public void zeroLengthRecord_Finished(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        c.setUseAllProvidedRecords(true);

        Record record = new Record();
        record.setMaxRecordLengthConfig(0);
        WorkflowTrace trace = runner.generateWorkflowTraceUntilSendingMessage(WorkflowTraceType.HANDSHAKE, HandshakeMessageType.FINISHED);
        trace.addTlsActions(
                new SendAction(new FinishedMessage()),
                new ReceiveAction(new AlertMessage())
        );

        SendAction finished = (SendAction) WorkflowTraceUtil.getFirstSendingActionForMessage(HandshakeMessageType.FINISHED, trace);
        finished.setRecords(record);

        runner.execute(trace, c).validateFinal(i -> {
            WorkflowTrace workflowtrace = i.getWorkflowTrace();
            Validator.receivedFatalAlert(i);

            AlertMessage msg = workflowtrace.getFirstReceivedMessage(AlertMessage.class);
            Validator.testAlertDescription(i, AlertDescription.UNEXPECTED_MESSAGE, msg);
        });
    }

    public ConditionEvaluationResult supportsRecordFragmentation() {
        if (context.getSiteReport().getResult(TlsAnalyzedProperty.SUPPORTS_RECORD_FRAGMENTATION) == TestResults.TRUE) {
            return ConditionEvaluationResult.enabled("");
        }
        return ConditionEvaluationResult.disabled("Target does not support Record fragmentation");
    }
    
    @TlsTest(description = "Handshake messages MUST NOT be interleaved "
            + "with other record types. That is, if a handshake message is split over two or more\n"
            + "records, there MUST NOT be any other records between them.")
    @ScopeLimitations(DerivationType.RECORD_LENGTH)
    @ScopeExtensions(DerivationType.ALERT)
    @RecordLayerCategory(SeverityLevel.LOW)
    @ComplianceCategory(SeverityLevel.HIGH)
    @AlertCategory(SeverityLevel.LOW)
    @MethodCondition(method = "supportsRecordFragmentation")
    @EnforcedSenderRestriction
    public void interleaveRecords(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace trace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        SendAction sendFinished = (SendAction) WorkflowTraceUtil.getFirstSendingActionForMessage(HandshakeMessageType.FINISHED, trace);
        AlertDescription selectedAlert = derivationContainer.getDerivation(AlertDerivation.class).getSelectedValue();
        
        Record finishedFragmentRecord = new Record();
        finishedFragmentRecord.setMaxRecordLengthConfig(10);
        Record alertRecord = new Record();
        
        //we add a record that will remain untouched by record layer but has
        //an alert set as explicit content
        alertRecord.setMaxRecordLengthConfig(0);
        alertRecord.setContentType(Modifiable.explicit(ProtocolMessageType.ALERT.getValue()));
        byte[] alertContent = new byte [] {AlertLevel.WARNING.getValue(), selectedAlert.getValue()};
        alertRecord.setProtocolMessageBytes(Modifiable.explicit(alertContent));
        
        sendFinished.setRecords(finishedFragmentRecord, alertRecord);

        trace.addTlsAction(new ReceiveAction(new AlertMessage()));

        runner.execute(trace, c).validateFinal(Validator::receivedFatalAlert);
    }
    
    @TlsTest(description = "Note that earlier versions of TLS did not clearly specify the record " +
        "layer version number value in all cases " +
        "(TLSPlaintext.legacy_record_version).  Servers will receive various " +
        "TLS 1.x versions in this field, but its value MUST always be ignored.")
    @RFC(number = 8446, section = "D.2.  Negotiating with an Older Client")
    @RecordLayerCategory(SeverityLevel.HIGH)
    @ComplianceCategory(SeverityLevel.CRITICAL)
    @ScopeExtensions(DerivationType.PROTOCOL_VERSION)
    @ExplicitValues(affectedTypes = DerivationType.PROTOCOL_VERSION,methods = "getRecordProtocolVersions")
    @Tag("new")
    public void ignoresInitialRecordVersion(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        byte[] selectedRecordVersion = derivationContainer.getDerivation(ProtocolVersionDerivation.class).getSelectedValue();
        
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        //manually insert HRR to manipulate very first hello
        if(runner.shouldInsertHelloRetryRequest()) {
            runner.insertHelloRetryRequest(workflowTrace, config.getDefaultSelectedNamedGroup());
        }
        runner.setAutoHelloRetryRequest(false);
        
        Record initialRecord = new Record();
        initialRecord.setComputations(new RecordCryptoComputations());
        initialRecord.setProtocolVersion(Modifiable.explicit(selectedRecordVersion));
        ((SendAction)workflowTrace.getFirstSendingAction()).setRecords(initialRecord);
        
        runner.execute(workflowTrace, config).validateFinal(Validator::executedAsPlanned);
    }
    
    public List<DerivationParameter> getRecordProtocolVersions(DerivationScope scope) {
        List<DerivationParameter> parameterValues = new LinkedList<>();
        parameterValues.add(new ProtocolVersionDerivation(new byte[] {0x03, 0x00}));
        parameterValues.add(new ProtocolVersionDerivation(new byte[] {0x03, 0x01}));
        parameterValues.add(new ProtocolVersionDerivation(new byte[] {0x03, 0x02}));
        parameterValues.add(new ProtocolVersionDerivation(new byte[] {0x03, 0x03}));
        parameterValues.add(new ProtocolVersionDerivation(new byte[] {0x03, 0x04}));
        parameterValues.add(new ProtocolVersionDerivation(new byte[] {0x03, 0x05}));
        return parameterValues;
    }
    
    @TlsTest(description = "legacy_record_version:  MUST be set to 0x0303 for all records " +
        "generated by a TLS 1.3 implementation other than an initial " +
        "ClientHello [...]" + 
        "In order to maximize backward " +
        "compatibility, a record containing an initial ClientHello SHOULD have " +
        "version 0x0301 (reflecting TLS 1.0) and a record containing a second " +
        "ClientHello or a ServerHello MUST have version 0x0303 (reflecting " +
        "TLS 1.2).")
    @InteroperabilityCategory(SeverityLevel.HIGH)
    @HandshakeCategory(SeverityLevel.HIGH)
    @ComplianceCategory(SeverityLevel.HIGH)
    @RecordLayerCategory(SeverityLevel.HIGH)
    @Tag("new")
    public void checkRecordProtocolVersion(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        
        runner.execute(workflowTrace, config).validateFinal(i -> {
            Validator.executedAsPlanned(i);
            for(ReceivingAction receiving : i.getWorkflowTrace().getReceivingActions()) {
                ReceiveAction receiveAction = (ReceiveAction) receiving;
                if(receiveAction.getReceivedRecords() != null && !receiveAction.getReceivedRecords().isEmpty()) {
                    for(Record record : receiveAction.getReceivedRecords()) {
                        if(record.getContentMessageType() != ProtocolMessageType.CHANGE_CIPHER_SPEC) {
                            assertArrayEquals("Record used wrong protocol version", record.getProtocolVersion().getValue(), ProtocolVersion.TLS12.getValue());
                        }
                    }
                }
            }
        });
    }
}
