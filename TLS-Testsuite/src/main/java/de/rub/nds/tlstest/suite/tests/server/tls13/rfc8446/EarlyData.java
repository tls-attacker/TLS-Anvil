/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.server.tls13.rfc8446;

import static org.junit.Assert.assertTrue;

import de.rub.nds.anvilcore.annotation.*;
import de.rub.nds.anvilcore.teststate.AnvilTestCase;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PreSharedKeyExtensionMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.RecordCryptoComputations;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipher;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipherFactory;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySet;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySetGenerator;
import de.rub.nds.tlsattacker.core.record.crypto.RecordDecryptor;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
import java.io.ByteArrayInputStream;
import java.util.List;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;

@ServerTest
public class EarlyData extends Tls13Test {

    public ConditionEvaluationResult supports0rtt() {
        if (context.getFeatureExtractionResult().getResult(TlsAnalyzedProperty.SUPPORTS_TLS13_0_RTT)
                == TestResults.TRUE) {
            return ConditionEvaluationResult.enabled("");
        } else {
            return ConditionEvaluationResult.disabled("Does not support 0-RTT early data");
        }
    }

    public ConditionEvaluationResult tls13multipleCipherSuites() {
        if (context.getFeatureExtractionResult().getResult(TlsAnalyzedProperty.SUPPORTS_TLS13_0_RTT)
                        == TestResults.TRUE
                && context.getFeatureExtractionResult().getSupportedTls13CipherSuites() != null
                && context.getFeatureExtractionResult().getSupportedTls13CipherSuites().size()
                        > 1) {
            return ConditionEvaluationResult.enabled("");
        } else {
            return ConditionEvaluationResult.disabled(
                    "Does not support 0-RTT early data or only offers one Cipher Suite");
        }
    }

    private CipherSuite getOtherSupportedCiphersuite(CipherSuite toTest) {
        for (CipherSuite cipherSuite :
                context.getFeatureExtractionResult().getSupportedTls13CipherSuites()) {
            if (cipherSuite != toTest) {
                return cipherSuite;
            }
        }
        return null;
    }

    @AnvilTest(id = "8446-3tUPL8K9nh")
    @MethodCondition(method = "supports0rtt")
    @Disabled
    public void selectedFirstIdentity(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);
        c.setAddPSKKeyExchangeModesExtension(true);
        c.setAddPreSharedKeyExtension(true);
        c.setAddEarlyDataExtension(true);

        WorkflowTrace workflowTrace =
                runner.generateWorkflowTraceUntilLastReceivingMessage(
                        WorkflowTraceType.FULL_ZERO_RTT, HandshakeMessageType.SERVER_HELLO);
        workflowTrace.addTlsAction(new ReceiveAction());

        State state = runner.execute(workflowTrace, c);

        WorkflowTrace trace = state.getWorkflowTrace();
        if (trace.getLastReceivedMessage(EncryptedExtensionsMessage.class)
                .containsExtension(ExtensionType.EARLY_DATA)) {
            assertTrue(
                    trace.getLastReceivedMessage(ServerHelloMessage.class)
                            .containsExtension(ExtensionType.PRE_SHARED_KEY));
            if (trace.getLastReceivedMessage(ServerHelloMessage.class)
                            .containsExtension(ExtensionType.PRE_SHARED_KEY)
                    == true) {
                assertTrue(
                        trace.getLastReceivedMessage(ServerHelloMessage.class)
                                .getExtension(PreSharedKeyExtensionMessage.class)
                                .getSelectedIdentity()
                                .getValue()
                                .equals(0));
            }
        }
    }

    @AnvilTest(id = "8446-QX4UnMXsbP")
    @MethodCondition(method = "tls13multipleCipherSuites")
    @Disabled
    public void cipherSuiteDisparity(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);
        c.setAddPSKKeyExchangeModesExtension(true);
        c.setAddPreSharedKeyExtension(true);
        c.setAddEarlyDataExtension(true);

        WorkflowTrace workflowTrace =
                runner.generateWorkflowTraceUntilLastReceivingMessage(
                        WorkflowTraceType.FULL_ZERO_RTT, HandshakeMessageType.SERVER_HELLO);
        workflowTrace.addTlsAction(new ReceiveAction());

        ClientHelloMessage secondHello = workflowTrace.getLastSendMessage(ClientHelloMessage.class);
        CipherSuite otherCipherSuite =
                getOtherSupportedCiphersuite(c.getDefaultSelectedCipherSuite());
        secondHello.setCipherSuites(Modifiable.explicit(otherCipherSuite.getByteValue()));
        secondHello.setCipherSuiteLength(
                Modifiable.explicit(otherCipherSuite.getByteValue().length));

        State state = runner.execute(workflowTrace, c);

        WorkflowTrace trace = state.getWorkflowTrace();
        if (trace.getLastReceivedMessage(EncryptedExtensionsMessage.class) != null) {
            assertTrue(
                    !trace.getLastReceivedMessage(EncryptedExtensionsMessage.class)
                            .containsExtension(ExtensionType.EARLY_DATA));
        }
    }

    @AnvilTest(id = "8446-wiNRa3novJ")
    @MethodCondition(method = "supports0rtt")
    @Disabled
    public void tlsVersionDisparity(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);
        c.setAddPSKKeyExchangeModesExtension(true);
        c.setAddPreSharedKeyExtension(true);
        c.setAddEarlyDataExtension(true);

        WorkflowTrace workflowTrace =
                runner.generateWorkflowTraceUntilLastReceivingMessage(
                        WorkflowTraceType.FULL_ZERO_RTT, HandshakeMessageType.SERVER_HELLO);
        workflowTrace.addTlsAction(new ReceiveAction());

        ClientHelloMessage secondHello = workflowTrace.getLastSendMessage(ClientHelloMessage.class);
        secondHello.setProtocolVersion(Modifiable.explicit(ProtocolVersion.TLS11.getValue()));

        State state = runner.execute(workflowTrace, c);

        WorkflowTrace trace = state.getWorkflowTrace();
        if (trace.getLastReceivedMessage(EncryptedExtensionsMessage.class) != null) {
            assertTrue(
                    !trace.getLastReceivedMessage(EncryptedExtensionsMessage.class)
                            .containsExtension(ExtensionType.EARLY_DATA));
        }
    }

    public boolean recordLengthAllowsModification(Integer lengthCandidate) {
        return lengthCandidate >= 50;
    }

    @AnvilTest(id = "8446-LSEXdVf1sN")
    @MethodCondition(method = "supports0rtt")
    @IncludeParameters({
        @IncludeParameter("APP_MSG_LENGHT"),
        @IncludeParameter("CIPHERTEXT_BITMASK")
    })
    @DynamicValueConstraints(
            affectedIdentifiers = "RECORD_LENGTH",
            methods = "recordLengthAllowsModification")
    @Disabled
    public void invalidCiphertext(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);
        c.setAddPSKKeyExchangeModesExtension(true);
        c.setAddPreSharedKeyExtension(true);
        c.setAddEarlyDataExtension(true);
        c.setPreserveMessageRecordRelation(true);
        byte[] modificationBitmask = parameterCombination.buildBitmask();

        WorkflowTrace workflowTrace =
                runner.generateWorkflowTraceUntilLastReceivingMessage(
                        WorkflowTraceType.FULL_ZERO_RTT, HandshakeMessageType.SERVER_HELLO);
        workflowTrace.addTlsAction(new ReceiveAction());

        SendAction cHello = (SendAction) workflowTrace.getLastSendingAction();
        cHello.getSendMessages()
                .remove(workflowTrace.getFirstSendMessage(ApplicationMessage.class));

        Record helloRecord = new Record();
        Record ccsCompatibilityRecord = new Record();
        Record earlyRecord = new Record();
        earlyRecord.setComputations(new RecordCryptoComputations());
        earlyRecord.getComputations().setCiphertext(Modifiable.xor(modificationBitmask, 0));

        ApplicationMessage earlyData = new ApplicationMessage();
        earlyData.setData(Modifiable.explicit(c.getDefaultApplicationMessageData().getBytes()));
        cHello.getSendMessages().add(earlyData);

        workflowTrace.getLastSendingAction().getSendRecords().add(helloRecord);
        if (c.getTls13BackwardsCompatibilityMode()) {
            workflowTrace.getLastSendingAction().getSendRecords().add(ccsCompatibilityRecord);
        }
        workflowTrace.getLastSendingAction().getSendRecords().add(earlyRecord);

        State state = runner.execute(workflowTrace, c);

        WorkflowTrace trace = state.getWorkflowTrace();
        List<Record> records = trace.getLastReceivingAction().getReceivedRecords();
        List<ProtocolMessage> msgs = trace.getLastReceivingAction().getReceivedMessages();
        if (records.size() > msgs.size()) {
            AlertMessage decAlert =
                    tryToDecryptWithAppSecrets(state.getTlsContext(), records.get(msgs.size()));
            if (decAlert != null) {
                msgs.add(decAlert);
            }
        }

        Validator.receivedFatalAlert(state, testCase, false);
        AlertMessage alert = state.getWorkflowTrace().getFirstReceivedMessage(AlertMessage.class);
        Validator.testAlertDescription(state, testCase, AlertDescription.BAD_RECORD_MAC, alert);
    }

    @AnvilTest(id = "8446-QSom3GGTZ1")
    @IncludeParameter("AUTH_TAG_BITMASK")
    @MethodCondition(method = "supports0rtt")
    @Disabled
    public void invalidAuthTag(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);
        c.setAddPSKKeyExchangeModesExtension(true);
        c.setAddPreSharedKeyExtension(true);
        c.setAddEarlyDataExtension(true);
        c.setPreserveMessageRecordRelation(true);
        byte[] modificationBitmask = parameterCombination.buildBitmask();

        WorkflowTrace workflowTrace =
                runner.generateWorkflowTraceUntilLastReceivingMessage(
                        WorkflowTraceType.FULL_ZERO_RTT, HandshakeMessageType.SERVER_HELLO);
        workflowTrace.addTlsAction(new ReceiveAction());

        SendAction cHello = (SendAction) workflowTrace.getLastSendingAction();
        cHello.getSendMessages()
                .remove(workflowTrace.getFirstSendMessage(ApplicationMessage.class));

        Record helloRecord = new Record();
        Record ccsCompatibilityRecord = new Record();
        Record earlyRecord = new Record();
        earlyRecord.setComputations(new RecordCryptoComputations());
        earlyRecord.getComputations().setAuthenticationTag(Modifiable.xor(modificationBitmask, 0));

        ApplicationMessage earlyData = new ApplicationMessage();
        earlyData.setData(Modifiable.explicit("test".getBytes()));
        cHello.getSendMessages().add(earlyData);

        workflowTrace.getLastSendingAction().getSendRecords().add(helloRecord);
        if (c.getTls13BackwardsCompatibilityMode()) {
            workflowTrace.getLastSendingAction().getSendRecords().add(ccsCompatibilityRecord);
        }
        workflowTrace.getLastSendingAction().getSendRecords().add(earlyRecord);

        State state = runner.execute(workflowTrace, c);

        WorkflowTrace trace = state.getWorkflowTrace();
        List<Record> records = trace.getLastReceivingAction().getReceivedRecords();
        List<ProtocolMessage> msgs = trace.getLastReceivingAction().getReceivedMessages();
        if (records.size() > msgs.size()) {
            AlertMessage decAlert =
                    tryToDecryptWithAppSecrets(state.getTlsContext(), records.get(msgs.size()));
            if (decAlert != null) {
                msgs.add(decAlert);
            }
        }

        Validator.receivedFatalAlert(state, testCase, false);
        AlertMessage alert = state.getWorkflowTrace().getFirstReceivedMessage(AlertMessage.class);
        Validator.testAlertDescription(state, testCase, AlertDescription.BAD_RECORD_MAC, alert);
    }

    private AlertMessage tryToDecryptWithAppSecrets(TlsContext context, Record record) {
        try {
            KeySet keySet =
                    KeySetGenerator.generateKeySet(
                            context,
                            ProtocolVersion.TLS13,
                            Tls13KeySetType.APPLICATION_TRAFFIC_SECRETS);
            RecordCipher recordCipher = RecordCipherFactory.getRecordCipher(context, keySet, false);
            RecordDecryptor dec = new RecordDecryptor(recordCipher, context);
            dec.decrypt(record);
            AlertMessage alert = new AlertMessage();
            alert.getParser(
                            context,
                            new ByteArrayInputStream(
                                    record.getCleanProtocolMessageBytes().getValue()))
                    .parse(alert);

            return alert;
        } catch (Exception ex) {
            return null;
        }
    }
}
