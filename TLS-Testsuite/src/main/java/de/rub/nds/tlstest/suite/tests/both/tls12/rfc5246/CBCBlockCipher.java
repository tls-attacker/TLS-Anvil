/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.both.tls12.rfc5246;

import static org.junit.Assert.assertTrue;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.DynamicValueConstraints;
import de.rub.nds.anvilcore.annotation.ValueConstraint;
import de.rub.nds.anvilcore.annotation.ValueConstraints;
import de.rub.nds.anvilcore.coffee4j.model.ModelFromScope;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.RecordCryptoComputations;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.*;
import de.rub.nds.tlstest.framework.annotations.categories.AlertCategory;
import de.rub.nds.tlstest.framework.annotations.categories.ComplianceCategory;
import de.rub.nds.tlstest.framework.annotations.categories.CryptoCategory;
import de.rub.nds.tlstest.framework.annotations.categories.InteroperabilityCategory;
import de.rub.nds.tlstest.framework.annotations.categories.RecordLayerCategory;
import de.rub.nds.tlstest.framework.annotations.categories.SecurityCategory;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.TlsParameterType;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@RFC(number = 5246, section = "6.2.3.2 CBC Block Cipher")
public class CBCBlockCipher extends Tls12Test {

    // tests are supposed to test validity with different padding sizes etc
    // splitting fragments into too small records would interfere with this
    public boolean recordLengthAllowsModification(Integer lengthCandidate) {
        return lengthCandidate >= 50;
    }

    @AnvilTest(
            description =
                    "Each uint8 in the padding data "
                            + "vector MUST be filled with the padding length value. The receiver "
                            + "MUST check this padding and MUST use the bad_record_mac alert to "
                            + "indicate padding errors.")
    @ModelFromScope(modelType = "CERTIFICATE")
    @SecurityCategory(SeverityLevel.HIGH)
    @ScopeExtensions({TlsParameterType.APP_MSG_LENGHT, TlsParameterType.PADDING_BITMASK})
    @ValueConstraints({@ValueConstraint(identifier = "CIPHER_SUITE", method = "isCBC")})
    @DynamicValueConstraints(
            affectedIdentifiers = "RECORD_LENGTH",
            methods = "recordLengthAllowsModification")
    @CryptoCategory(SeverityLevel.CRITICAL)
    @RecordLayerCategory(SeverityLevel.CRITICAL)
    @AlertCategory(SeverityLevel.HIGH)
    @ComplianceCategory(SeverityLevel.HIGH)
    public void invalidCBCPadding(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        byte[] modificationBitmask = derivationContainer.buildBitmask();

        Record record = new Record();
        record.setComputations(new RecordCryptoComputations());
        record.getComputations().setPadding(Modifiable.xor(modificationBitmask, 0));

        ApplicationMessage appData = new ApplicationMessage();
        appData.setData(Modifiable.explicit(c.getDefaultApplicationMessageData().getBytes()));

        SendAction sendAction = new SendAction(appData);
        sendAction.setRecords(record);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        workflowTrace.addTlsActions(sendAction, new ReceiveAction(new AlertMessage()));

        runner.execute(workflowTrace, c)
                .validateFinal(
                        i -> {
                            WorkflowTrace trace = i.getWorkflowTrace();
                            Validator.receivedFatalAlert(i);

                            AlertMessage msg = trace.getFirstReceivedMessage(AlertMessage.class);
                            Validator.testAlertDescription(i, AlertDescription.BAD_RECORD_MAC, msg);
                        });
    }

    @AnvilTest(
            description =
                    "bad_record_mac[...]This alert also MUST be returned if an alert is sent because "
                            + "a TLSCiphertext decrypted in an invalid way: either it wasn’t an "
                            + "even multiple of the block length, or its padding values, when "
                            + "checked, weren’t correct.")
    @RFC(number = 5246, section = "7.2.2. Error Alerts")
    @ModelFromScope(modelType = "CERTIFICATE")
    @SecurityCategory(SeverityLevel.HIGH)
    @ScopeExtensions(TlsParameterType.CIPHERTEXT_BITMASK)
    @ValueConstraints({
        @ValueConstraint(identifier = "CIPHER_SUITE", method = "isCBC"),
    })
    @DynamicValueConstraints(
            affectedIdentifiers = "RECORD_LENGTH",
            methods = "recordLengthAllowsModification")
    @CryptoCategory(SeverityLevel.CRITICAL)
    @RecordLayerCategory(SeverityLevel.CRITICAL)
    @AlertCategory(SeverityLevel.HIGH)
    @ComplianceCategory(SeverityLevel.HIGH)
    public void invalidCipherText(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        byte[] modificationBitmask = derivationContainer.buildBitmask();

        Record record = new Record();
        record.setComputations(new RecordCryptoComputations());
        if (c.isAddEncryptThenMacExtension()) {
            // modify record bytes as ciphertext is used to compute mac
            record.setProtocolMessageBytes(Modifiable.xor(modificationBitmask, 0));
        } else {
            record.getComputations().setCiphertext(Modifiable.xor(modificationBitmask, 0));
        }

        ApplicationMessage appData = new ApplicationMessage();
        appData.setData(Modifiable.explicit("test".getBytes()));

        SendAction sendAction = new SendAction(appData);
        sendAction.setRecords(record);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        workflowTrace.addTlsActions(sendAction, new ReceiveAction(new AlertMessage()));

        runner.execute(workflowTrace, c)
                .validateFinal(
                        i -> {
                            WorkflowTrace trace = i.getWorkflowTrace();
                            Validator.receivedFatalAlert(i);

                            AlertMessage msg = trace.getFirstReceivedMessage(AlertMessage.class);
                            Validator.testAlertDescription(i, AlertDescription.BAD_RECORD_MAC, msg);
                            if (msg != null
                                    && msg.getDescription().getValue()
                                            == AlertDescription.DECRYPTION_FAILED_RESERVED
                                                    .getValue()) {
                                // 7.2.2. Error Alerts - decryption_failed_RESERVED
                                // This alert was used in some earlier versions of TLS, and may have
                                // permitted certain attacks against the CBC mode [CBCATT]. It MUST
                                // NOT be sent by compliant implementations.
                                throw new AssertionError(
                                        "Target sent deprecated decryption_failed_RESERVERD alert in response to invalid Ciphertext");
                            }
                        });
    }

    @AnvilTest(
            description =
                    "bad_record_mac[...]This alert is returned if a record is received with an incorrect "
                            + "MAC.")
    @RFC(number = 5246, section = "7.2.2. Error Alerts")
    @ModelFromScope(modelType = "CERTIFICATE")
    @SecurityCategory(SeverityLevel.HIGH)
    @ScopeExtensions(TlsParameterType.MAC_BITMASK)
    @ValueConstraints({
        @ValueConstraint(identifier = "CIPHER_SUITE", method = "isCBC"),
    })
    @DynamicValueConstraints(
            affectedIdentifiers = "RECORD_LENGTH",
            methods = "recordLengthAllowsModification")
    @CryptoCategory(SeverityLevel.HIGH)
    @RecordLayerCategory(SeverityLevel.HIGH)
    @AlertCategory(SeverityLevel.HIGH)
    @ComplianceCategory(SeverityLevel.HIGH)
    public void invalidMAC(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        byte[] bitmask = derivationContainer.buildBitmask();
        Record record = new Record();
        record.setComputations(new RecordCryptoComputations());
        record.getComputations().setMac(Modifiable.xor(bitmask, 0));

        ApplicationMessage appData = new ApplicationMessage();
        appData.setData(Modifiable.explicit("test".getBytes()));

        SendAction sendAction = new SendAction(appData);
        sendAction.setRecords(record);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        workflowTrace.addTlsActions(sendAction, new ReceiveAction(new AlertMessage()));

        runner.execute(workflowTrace, c)
                .validateFinal(
                        i -> {
                            WorkflowTrace trace = i.getWorkflowTrace();
                            Validator.receivedFatalAlert(i);

                            AlertMessage msg = trace.getFirstReceivedMessage(AlertMessage.class);
                            Validator.testAlertDescription(i, AlertDescription.BAD_RECORD_MAC, msg);
                        });
    }

    @AnvilTest(
            description =
                    "A sequence number is incremented after each "
                            + "record: specifically, the first record transmitted under a "
                            + "particular connection state MUST use sequence number 0.")
    @RFC(number = 5246, section = "6.1. Connection States")
    @ModelFromScope(modelType = "CERTIFICATE")
    @ValueConstraints({
        @ValueConstraint(identifier = "CIPHER_SUITE", method = "isCBC"),
    })
    @CryptoCategory(SeverityLevel.MEDIUM)
    @RecordLayerCategory(SeverityLevel.CRITICAL)
    @InteroperabilityCategory(SeverityLevel.CRITICAL)
    @ComplianceCategory(SeverityLevel.CRITICAL)
    @Tag("new")
    public void checkReceivedMac(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        runner.execute(workflowTrace, config)
                .validateFinal(
                        i -> {
                            Validator.executedAsPlanned(i);
                            boolean sawCCS = false;
                            for (Record record :
                                    WorkflowTraceUtil.getAllReceivedRecords(i.getWorkflowTrace())) {
                                if (record.getContentMessageType()
                                        == ProtocolMessageType.CHANGE_CIPHER_SPEC) {
                                    sawCCS = true;
                                }
                                if (sawCCS
                                        && record.getContentMessageType()
                                                == ProtocolMessageType.HANDSHAKE) {
                                    Record encryptedFin = record;
                                    assertTrue(
                                            "Finished record MAC invalid - is the SQN correct?",
                                            encryptedFin.getComputations().getMacValid());
                                } else if (sawCCS
                                        && record.getContentMessageType()
                                                == ProtocolMessageType.APPLICATION_DATA) {
                                    Record encryptedFin = record;
                                    assertTrue(
                                            "App Data record MAC invalid",
                                            encryptedFin.getComputations().getMacValid());
                                }
                            }
                        });
    }
}
