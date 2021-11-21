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
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.RecordCryptoComputations;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.*;
import de.rub.nds.tlstest.framework.annotations.categories.AlertCategory;
import de.rub.nds.tlstest.framework.annotations.categories.ComplianceCategory;
import de.rub.nds.tlstest.framework.annotations.categories.SecurityCategory;
import de.rub.nds.tlstest.framework.coffee4j.model.ModelFromScope;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.constants.TestResult;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.DerivationScope;
import de.rub.nds.tlstest.framework.model.DerivationType;
import de.rub.nds.tlstest.framework.model.ModelType;
import de.rub.nds.tlstest.framework.model.constraint.ConditionalConstraint;
import de.rub.nds.tlstest.framework.model.constraint.ConstraintHelper;
import de.rub.nds.tlstest.framework.model.derivationParameter.DerivationFactory;
import de.rub.nds.tlstest.framework.model.derivationParameter.PaddingBitmaskDerivation;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import java.util.LinkedList;
import java.util.List;
import org.junit.jupiter.api.Tag;

import org.junit.jupiter.params.aggregator.ArgumentsAccessor;
import de.rub.nds.tlstest.framework.annotations.categories.CryptoCategory;
import de.rub.nds.tlstest.framework.annotations.categories.RecordLayerCategory;


@RFC(number = 5246, section = "6.2.3.2 CBC Block Cipher")
public class CBCBlockCipher extends Tls12Test {

    //tests are supposed to test validity with different padding sizes etc
    //splitting fragments into too small records would interfere with this
    public boolean recordLengthAllowsModification(Integer lengthCandidate) {
        return lengthCandidate >= 50;
    }

    @TlsTest(description = "Each uint8 in the padding data " +
            "vector MUST be filled with the padding length value. The receiver " +
            "MUST check this padding and MUST use the bad_record_mac alert to " +
            "indicate padding errors.")
    @ModelFromScope(baseModel = ModelType.CERTIFICATE)
    @SecurityCategory(SeverityLevel.HIGH)
    @ScopeExtensions({DerivationType.APP_MSG_LENGHT, DerivationType.PADDING_BITMASK})
    @ValueConstraints(affectedTypes = {DerivationType.CIPHERSUITE}, methods = "isCBC")
    @DynamicValueConstraints(affectedTypes = DerivationType.RECORD_LENGTH, methods = "recordLengthAllowsModification")
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
        workflowTrace.addTlsActions(
                sendAction,
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(workflowTrace, c).validateFinal(i -> {
            WorkflowTrace trace = i.getWorkflowTrace();
            Validator.receivedFatalAlert(i);

            AlertMessage msg = trace.getFirstReceivedMessage(AlertMessage.class);
            Validator.testAlertDescription(i, AlertDescription.BAD_RECORD_MAC, msg);
        });

    }

    @TlsTest(description = "bad_record_mac - [...] This alert also MUST be returned if an alert is sent because " +
            "a TLSCiphertext decrypted in an invalid way: either it wasn’t an " +
            "even multiple of the block length, or its padding values, when " +
            "checked, weren’t correct.")
    @RFC(number = 5246, section = "7.2.2. Error Alerts")
    @ModelFromScope(baseModel = ModelType.CERTIFICATE)
    @SecurityCategory(SeverityLevel.HIGH)
    @ScopeExtensions(DerivationType.CIPHERTEXT_BITMASK)
    @ValueConstraints(affectedTypes = DerivationType.CIPHERSUITE, methods = "isCBC")
    @DynamicValueConstraints(affectedTypes = DerivationType.RECORD_LENGTH, methods = "recordLengthAllowsModification")
    @CryptoCategory(SeverityLevel.CRITICAL)
    @RecordLayerCategory(SeverityLevel.CRITICAL)
    @AlertCategory(SeverityLevel.HIGH)
    @ComplianceCategory(SeverityLevel.HIGH)
    public void invalidCipherText(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        byte[] modificationBitmask = derivationContainer.buildBitmask();
        
        Record record = new Record();
        record.setComputations(new RecordCryptoComputations());
        if(c.isAddEncryptThenMacExtension()) {
           //modify record bytes as ciphertext is used to compute mac
           record.setProtocolMessageBytes(Modifiable.xor(modificationBitmask, 0));
        } else {
           record.getComputations().setCiphertext(Modifiable.xor(modificationBitmask, 0)); 
        }
        

        ApplicationMessage appData = new ApplicationMessage();
        appData.setData(Modifiable.explicit("test".getBytes()));

        SendAction sendAction = new SendAction(appData);
        sendAction.setRecords(record);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        workflowTrace.addTlsActions(
                sendAction,
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(workflowTrace, c).validateFinal(i -> {
            WorkflowTrace trace = i.getWorkflowTrace();
            Validator.receivedFatalAlert(i);

            AlertMessage msg = trace.getFirstReceivedMessage(AlertMessage.class);
            Validator.testAlertDescription(i, AlertDescription.BAD_RECORD_MAC, msg);
            if(msg != null && msg.getDescription().getValue() == AlertDescription.DECRYPTION_FAILED_RESERVED.getValue()) {
                //7.2.2. Error Alerts - decryption_failed_RESERVED
                //This alert was used in some earlier versions of TLS, and may have
                //permitted certain attacks against the CBC mode [CBCATT]. It MUST
                //NOT be sent by compliant implementations.
                throw new AssertionError("Target sent deprecated decryption_failed_RESERVERD alert in response to invalid Ciphertext");
            }
        });
    }


    @TlsTest(description = "bad_record_mac - This alert is returned if a record is received with an incorrect " +
            "MAC.")
    @RFC(number = 5246, section = "7.2.2. Error Alerts")
    @ModelFromScope(baseModel = ModelType.CERTIFICATE)
    @SecurityCategory(SeverityLevel.HIGH)
    @ScopeExtensions(DerivationType.MAC_BITMASK)
    @ValueConstraints(affectedTypes = DerivationType.CIPHERSUITE, methods = "isCBC")
    @DynamicValueConstraints(affectedTypes = DerivationType.RECORD_LENGTH, methods = "recordLengthAllowsModification")
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
        workflowTrace.addTlsActions(
                sendAction,
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(workflowTrace, c).validateFinal(i -> {
            WorkflowTrace trace = i.getWorkflowTrace();
            Validator.receivedFatalAlert(i);

            AlertMessage msg = trace.getFirstReceivedMessage(AlertMessage.class);
            Validator.testAlertDescription(i, AlertDescription.BAD_RECORD_MAC, msg);
        });
    }

}
