/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.both.tls12.rfc5246;

import static org.junit.Assert.assertTrue;

import de.rub.nds.anvilcore.annotation.*;
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
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

public class CBCBlockCipher extends Tls12Test {

    // tests are supposed to test validity with different padding sizes etc
    // splitting fragments into too small records would interfere with this
    public boolean recordLengthAllowsModification(Integer lengthCandidate) {
        return lengthCandidate >= 50;
    }

    @AnvilTest(id = "5246-RNB9LX21i9")
    @ModelFromScope(modelType = "CERTIFICATE")
    @IncludeParameters({@IncludeParameter("APP_MSG_LENGHT"), @IncludeParameter("PADDING_BITMASK")})
    @ValueConstraints({@ValueConstraint(identifier = "CIPHER_SUITE", method = "isCBC")})
    @DynamicValueConstraints(
            affectedIdentifiers = "RECORD_LENGTH",
            methods = "recordLengthAllowsModification")
    public void invalidCBCPadding(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        byte[] modificationBitmask = parameterCombination.buildBitmask();

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

    @AnvilTest(id = "5246-VC1baM1Mn1")
    @ModelFromScope(modelType = "CERTIFICATE")
    @IncludeParameter("CIPHERTEXT_BITMASK")
    @ValueConstraints({
        @ValueConstraint(identifier = "CIPHER_SUITE", method = "isCBC"),
    })
    @DynamicValueConstraints(
            affectedIdentifiers = "RECORD_LENGTH",
            methods = "recordLengthAllowsModification")
    public void invalidCipherText(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        byte[] modificationBitmask = parameterCombination.buildBitmask();

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

    @AnvilTest(id = "5246-JBqS2uGywY")
    @ModelFromScope(modelType = "CERTIFICATE")
    @IncludeParameter("MAC_BITMASK")
    @ValueConstraints({
        @ValueConstraint(identifier = "CIPHER_SUITE", method = "isCBC"),
    })
    @DynamicValueConstraints(
            affectedIdentifiers = "RECORD_LENGTH",
            methods = "recordLengthAllowsModification")
    public void invalidMAC(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        byte[] bitmask = parameterCombination.buildBitmask();
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

    @AnvilTest(id = "5246-BWb6uwVEte")
    @ModelFromScope(modelType = "CERTIFICATE")
    @ValueConstraints({
        @ValueConstraint(identifier = "CIPHER_SUITE", method = "isCBC"),
    })
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
