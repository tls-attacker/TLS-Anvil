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
import de.rub.nds.tlstest.framework.annotations.ExplicitModelingConstraints;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.ScopeExtensions;
import de.rub.nds.tlstest.framework.annotations.ScopeLimitations;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.annotations.ValueConstraints;
import de.rub.nds.tlstest.framework.annotations.categories.Security;
import de.rub.nds.tlstest.framework.coffee4j.model.ModelFromScope;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
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


@RFC(number = 5264, section = "6.2.3.2 CBC Block Cipher")
public class CBCBlockCipher extends Tls12Test {

    @TlsTest(description = "Each uint8 in the padding data " +
            "vector MUST be filled with the padding length value. The receiver " +
            "MUST check this padding and MUST use the bad_record_mac alert to " +
            "indicate padding errors.")
    @ModelFromScope(baseModel = ModelType.CERTIFICATE)
    @Security(SeverityLevel.HIGH)
    @ScopeExtensions({DerivationType.APP_MSG_LENGHT, DerivationType.PADDING_BITMASK})
    @ValueConstraints(affectedTypes = {DerivationType.CIPHERSUITE}, methods = "isCBC")
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
            if (msg == null || msg.getDescription().getValue() != AlertDescription.BAD_RECORD_MAC.getValue()) {
                throw new AssertionError("Received non expected alert message with invalid CBC padding");
            }
        });

    }

    @TlsTest(description = "The padding length MUST be such that the total size of the " +
            "GenericBlockCipher structure is a multiple of the cipher’s block " +
            "length. Legal values range from zero to 255, inclusive. This " +
            "length specifies the length of the padding field exclusive of the " +
            "padding_length field itself.")
    @ModelFromScope(baseModel = ModelType.CERTIFICATE)
    @Security(SeverityLevel.HIGH)
    @ScopeExtensions(DerivationType.CIPHERTEXT_BITMASK)
    @ValueConstraints(affectedTypes = DerivationType.CIPHERSUITE, methods = "isCBC")
    public void invalidCipherText(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        byte[] modificationBitmask = derivationContainer.buildBitmask();
        
        Record record = new Record();
        record.setComputations(new RecordCryptoComputations());
        record.getComputations().setCiphertext(Modifiable.xor(modificationBitmask, 0));

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
            if (msg == null || msg.getDescription().getValue() != AlertDescription.BAD_RECORD_MAC.getValue()) {
                throw new AssertionError("Received non expected alert message with invalid CBC padding");
            }
        });
    }


    @TlsTest(description = "The padding length MUST be such that the total size of the " +
            "GenericBlockCipher structure is a multiple of the cipher’s block " +
            "length. Legal values range from zero to 255, inclusive. This " +
            "length specifies the length of the padding field exclusive of the " +
            "padding_length field itself.")
    @ModelFromScope(baseModel = ModelType.CERTIFICATE)
    @Security(SeverityLevel.HIGH)
    @ScopeExtensions(DerivationType.MAC_BITMASK)
    @ValueConstraints(affectedTypes = DerivationType.CIPHERSUITE, methods = "isCBC")
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
            if (msg == null || msg.getDescription().getValue() != AlertDescription.BAD_RECORD_MAC.getValue()) {
                throw new AssertionError("Received non expected alert message with invalid CBC padding");
            }
        });
    }
    
    public List<ConditionalConstraint> getPaddingBitmaskConstraints(DerivationScope scope) {
        PaddingBitmaskDerivation paddingBitmaskDerivation = (PaddingBitmaskDerivation) DerivationFactory.getInstance(DerivationType.PADDING_BITMASK);
        List<ConditionalConstraint> condConstraints = new LinkedList<>();

        if (ConstraintHelper.multipleBlocksizesModeled(scope)) {
            condConstraints.add(paddingBitmaskDerivation.getMustBeWithinBlocksizeConstraint());
        }

        condConstraints.add(paddingBitmaskDerivation.getMustNotExceedPaddingLengthConstraint(scope, true));
        condConstraints.add(paddingBitmaskDerivation.getMustNotResultInZeroPaddingLength(scope, true));
        return condConstraints;
    }
    
    @TlsTest(description = "The padding length MUST be such that the total size of the " +
            "GenericBlockCipher structure is a multiple of the cipher’s block " +
            "length. Legal values range from zero to 255, inclusive. This " +
            "length specifies the length of the padding field exclusive of the " +
            "padding_length field itself.")
    @ModelFromScope(baseModel = ModelType.CERTIFICATE)
    @Security(SeverityLevel.HIGH)
    @ValueConstraints(affectedTypes = DerivationType.CIPHERSUITE, methods = "isCBC")
    public void missingMAC(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);

        Record record = new Record();
        record.setComputations(new RecordCryptoComputations());
        record.getComputations().setMac(Modifiable.explicit(new byte[0]));

        performMissingMACTest(runner, config, record);
    }
    
    @TlsTest(description = "The padding length MUST be such that the total size of the " +
            "GenericBlockCipher structure is a multiple of the cipher’s block " +
            "length. Legal values range from zero to 255, inclusive. This " +
            "length specifies the length of the padding field exclusive of the " +
            "padding_length field itself.")
    @ModelFromScope(baseModel = ModelType.CERTIFICATE)
    @Security(SeverityLevel.HIGH)
    @ValueConstraints(affectedTypes = DerivationType.CIPHERSUITE, methods = "isCBC")
    @ScopeExtensions({DerivationType.APP_MSG_LENGHT, DerivationType.PADDING_BITMASK})
    @ExplicitModelingConstraints(affectedTypes = DerivationType.PADDING_BITMASK, methods = "getPaddingBitmaskConstraints")
    public void missingMACinvalidPadding(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        byte[] paddingBitmask = derivationContainer.buildBitmask();
        
        Record record = new Record();
        record.setComputations(new RecordCryptoComputations());
        record.getComputations().setMac(Modifiable.explicit(new byte[0]));
        record.getComputations().setPadding(Modifiable.xor(paddingBitmask, 0));

        performMissingMACTest(runner, config, record);
    }
    
    private void performMissingMACTest(WorkflowRunner runner, Config config, Record preparedRecord) {
        ApplicationMessage appData = new ApplicationMessage(config);

        SendAction sendAction = new SendAction(appData);
        sendAction.setRecords(preparedRecord);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        workflowTrace.addTlsActions(
                sendAction,
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(workflowTrace, config).validateFinal(i -> {
            WorkflowTrace trace = i.getWorkflowTrace();
            Validator.receivedFatalAlert(i);

            //for encrypt-then-MAC, this might result in a Decode Error
            if(!config.isAddEncryptThenMacExtension()) {
                AlertMessage msg = trace.getFirstReceivedMessage(AlertMessage.class);
                Validator.testAlertDescription(i, AlertDescription.BAD_RECORD_MAC, msg);
                if (msg == null || msg.getDescription().getValue() != AlertDescription.BAD_RECORD_MAC.getValue()) {
                    throw new AssertionError("Received non expected alert message with invalid CBC padding");
                }
            }
        });
    }

}
