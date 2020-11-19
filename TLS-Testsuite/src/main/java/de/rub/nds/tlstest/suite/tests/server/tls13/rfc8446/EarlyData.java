package de.rub.nds.tlstest.suite.tests.server.tls13.rfc8446;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.Tls13KeySetType;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.protocol.handler.AlertHandler;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.EncryptedExtensionsMessage;
import de.rub.nds.tlsattacker.core.protocol.message.EndOfEarlyDataMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PreSharedKeyExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.AlertParser;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.RecordCryptoComputations;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipher;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipherFactory;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySet;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySetGenerator;
import de.rub.nds.tlsattacker.core.record.crypto.RecordDecryptor;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.MessageAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.SendMessageHelper;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.MethodCondition;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.ScopeExtensions;
import de.rub.nds.tlstest.framework.annotations.ServerTest;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.execution.AnnotatedState;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.DerivationType;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import static org.junit.Assert.assertTrue;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@ServerTest
@RFC(number = 8446, section = "4.2.10 Early Data Indication")
public class EarlyData extends Tls13Test {

    public ConditionEvaluationResult supports0rtt() {
        if (context.getSiteReport().getResult(AnalyzedProperty.SUPPORTS_TLS13_0_RTT) == TestResult.TRUE) {
            return ConditionEvaluationResult.enabled("");
        } else {
            return ConditionEvaluationResult.disabled("Does not support 0-RTT early data");
        }
    }

    public ConditionEvaluationResult tls13multipleCipherSuites() {
        if (context.getSiteReport().getResult(AnalyzedProperty.SUPPORTS_TLS13_0_RTT) == TestResult.TRUE && context.getSiteReport().getSupportedTls13CipherSuites() != null && context.getSiteReport().getSupportedTls13CipherSuites().size() > 1) {
            return ConditionEvaluationResult.enabled("");
        } else {
            return ConditionEvaluationResult.disabled("Does not support 0-RTT early data or only offers one Cipher Suite");
        }
    }

    private CipherSuite getOtherSupportedCiphersuite(CipherSuite toTest) {
        for (CipherSuite cipherSuite : context.getSiteReport().getSupportedTls13CipherSuites()) {
            if (cipherSuite != toTest) {
                return cipherSuite;
            }
        }
        return null;
    }

    @TlsTest(description = "If the server supplies an \"early_data\" extension, the client MUST"
            + "verify that the server's selected_identity is 0.") //todo: does this suffice as an implicit instruction for the server?
    @RFC(number = 8446, section = "4.2.10 Early Data Indication")
    @MethodCondition(method = "supports0rtt")
    public void selectedFirstIdentity(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        c.setAddPSKKeyExchangeModesExtension(true);
        c.setAddPreSharedKeyExtension(true);
        c.setAddEarlyDataExtension(true);

        WorkflowTrace workflowTrace = runner.generateWorkflowTraceUntilLastReceivingMessage(WorkflowTraceType.FULL_ZERO_RTT, HandshakeMessageType.SERVER_HELLO);
        workflowTrace.addTlsAction(new ReceiveAction());

        runner.execute(workflowTrace, c).validateFinal(i -> {
            WorkflowTrace trace = i.getWorkflowTrace();
            if (trace.getLastReceivedMessage(EncryptedExtensionsMessage.class).containsExtension(ExtensionType.EARLY_DATA)) {
                assertTrue(trace.getLastReceivedMessage(ServerHelloMessage.class).containsExtension(ExtensionType.PRE_SHARED_KEY));
                if (trace.getLastReceivedMessage(ServerHelloMessage.class).containsExtension(ExtensionType.PRE_SHARED_KEY) == true) {
                    assertTrue(trace.getLastReceivedMessage(ServerHelloMessage.class).getExtension(PreSharedKeyExtensionMessage.class).getSelectedIdentity().getValue().equals(0));
                }
            }

        });
    }

    @TlsTest(description = "[The server] MUST verify that the"
            + "following values are the same as those associated with the"
            + "selected PSK: [...] The selected cipher suite [...]"
            + "If any of these checks fail, the server MUST NOT respond with the"
            + "extension")
    @RFC(number = 8446, section = "4.2.10 Early Data Indication")
    @MethodCondition(method = "tls13multipleCipherSuites")
    public void cipherSuiteDisparity(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        c.setAddPSKKeyExchangeModesExtension(true);
        c.setAddPreSharedKeyExtension(true);
        c.setAddEarlyDataExtension(true);

        WorkflowTrace workflowTrace = runner.generateWorkflowTraceUntilLastReceivingMessage(WorkflowTraceType.FULL_ZERO_RTT, HandshakeMessageType.SERVER_HELLO);
        workflowTrace.addTlsAction(new ReceiveAction());

        ClientHelloMessage secondHello = workflowTrace.getLastSendMessage(ClientHelloMessage.class);
        CipherSuite otherCipherSuite = getOtherSupportedCiphersuite(c.getDefaultSelectedCipherSuite());
        secondHello.setCipherSuites(Modifiable.explicit(otherCipherSuite.getByteValue()));
        secondHello.setCipherSuiteLength(Modifiable.explicit(otherCipherSuite.getByteValue().length));

        runner.execute(workflowTrace, c).validateFinal(i -> {
            WorkflowTrace trace = i.getWorkflowTrace();
            if (trace.getLastReceivedMessage(EncryptedExtensionsMessage.class) != null) {
                assertTrue(!trace.getLastReceivedMessage(EncryptedExtensionsMessage.class).containsExtension(ExtensionType.EARLY_DATA));
            }
        });
    }

    @TlsTest(description = "[The server] MUST verify that the"
            + "following values are the same as those associated with the"
            + "selected PSK: [...] The TLS version number [...]"
            + "If any of these checks fail, the server MUST NOT respond with the"
            + "extension")
    @RFC(number = 8446, section = "4.2.10 Early Data Indication")
    @MethodCondition(method = "supports0rtt")
    public void tlsVersionDisparity(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        c.setAddPSKKeyExchangeModesExtension(true);
        c.setAddPreSharedKeyExtension(true);
        c.setAddEarlyDataExtension(true);

        WorkflowTrace workflowTrace = runner.generateWorkflowTraceUntilLastReceivingMessage(WorkflowTraceType.FULL_ZERO_RTT, HandshakeMessageType.SERVER_HELLO);
        workflowTrace.addTlsAction(new ReceiveAction());

        ClientHelloMessage secondHello = workflowTrace.getLastSendMessage(ClientHelloMessage.class);
        secondHello.setProtocolVersion(Modifiable.explicit(ProtocolVersion.TLS11.getValue()));

        runner.execute(workflowTrace, c).validateFinal(i -> {
            WorkflowTrace trace = i.getWorkflowTrace();
            if (trace.getLastReceivedMessage(EncryptedExtensionsMessage.class) != null) {
                assertTrue(!trace.getLastReceivedMessage(EncryptedExtensionsMessage.class).containsExtension(ExtensionType.EARLY_DATA));
            }
        });
    }

    @TlsTest(description = "If the server chooses to accept the \"early_data\" extension, then it"
            + "MUST comply with the same error-handling requirements specified for"
            + "all records when processing early data records.  Specifically, if the\n"
            + "server fails to decrypt a 0-RTT record following an accepted\n"
            + "\"early_data\" extension, it MUST terminate the connection with a\n"
            + "\"bad_record_mac\" alert as per Section 5.2.")
    @RFC(number = 8446, section = "4.2.10 Early Data Indication")
    @MethodCondition(method = "supports0rtt")
    @ScopeExtensions({DerivationType.APP_MSG_LENGHT, DerivationType.CIPHERTEXT_BITMASK})
    public void invalidCiphertext(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        c.setAddPSKKeyExchangeModesExtension(true);
        c.setAddPreSharedKeyExtension(true);
        c.setAddEarlyDataExtension(true);
        c.setPreserveMessageRecordRelation(true);
        byte[] modificationBitmask = derivationContainer.buildBitmask();

        WorkflowTrace workflowTrace = runner.generateWorkflowTraceUntilLastReceivingMessage(WorkflowTraceType.FULL_ZERO_RTT, HandshakeMessageType.SERVER_HELLO);
        workflowTrace.addTlsAction(new ReceiveAction());

        SendAction cHello = (SendAction) workflowTrace.getLastSendingAction();
        cHello.getSendMessages().remove(workflowTrace.getFirstSendMessage(ApplicationMessage.class));

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

        runner.execute(workflowTrace, c).validateFinal(i -> {
            WorkflowTrace trace = i.getWorkflowTrace();
            List<AbstractRecord> records = trace.getLastReceivingAction().getReceivedRecords();
            List<ProtocolMessage> msgs = trace.getLastReceivingAction().getReceivedMessages();
            if (records.size() > msgs.size()) {
                AlertMessage decAlert = tryToDecryptWithAppSecrets(i.getState().getTlsContext(), records.get(msgs.size()));
                if (decAlert != null) {
                    msgs.add(decAlert);
                }
            }

            Validator.receivedFatalAlert(i, false);
            AlertMessage alert = i.getWorkflowTrace().getFirstReceivedMessage(AlertMessage.class);
            if (alert == null) {
                return;
            }
            Validator.testAlertDescription(i, AlertDescription.BAD_RECORD_MAC, alert);
        });
    }

    @TlsTest(description = "If the server chooses to accept the \"early_data\" extension, then it"
            + "MUST comply with the same error-handling requirements specified for"
            + "all records when processing early data records.  Specifically, if the\n"
            + "server fails to decrypt a 0-RTT record following an accepted\n"
            + "\"early_data\" extension, it MUST terminate the connection with a\n"
            + "\"bad_record_mac\" alert as per Section 5.2.")
    @RFC(number = 8446, section = "4.2.10 Early Data Indication")
    @ScopeExtensions(DerivationType.AUTH_TAG_BITMASK)
    @MethodCondition(method = "supports0rtt")
    public void invalidAuthTag(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        c.setAddPSKKeyExchangeModesExtension(true);
        c.setAddPreSharedKeyExtension(true);
        c.setAddEarlyDataExtension(true);
        c.setPreserveMessageRecordRelation(true);
        byte[] modificationBitmask = derivationContainer.buildBitmask();
        
        WorkflowTrace workflowTrace = runner.generateWorkflowTraceUntilLastReceivingMessage(WorkflowTraceType.FULL_ZERO_RTT, HandshakeMessageType.SERVER_HELLO);
        workflowTrace.addTlsAction(new ReceiveAction());

        SendAction cHello = (SendAction) workflowTrace.getLastSendingAction();
        cHello.getSendMessages().remove(workflowTrace.getFirstSendMessage(ApplicationMessage.class));

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

        runner.execute(workflowTrace, c).validateFinal(i -> {
            WorkflowTrace trace = i.getWorkflowTrace();
            List<AbstractRecord> records = trace.getLastReceivingAction().getReceivedRecords();
            List<ProtocolMessage> msgs = trace.getLastReceivingAction().getReceivedMessages();
            if (records.size() > msgs.size()) {
                AlertMessage decAlert = tryToDecryptWithAppSecrets(i.getState().getTlsContext(), records.get(msgs.size()));
                if (decAlert != null) {
                    msgs.add(decAlert);
                }
            }

            Validator.receivedFatalAlert(i, false);
            AlertMessage alert = i.getWorkflowTrace().getFirstReceivedMessage(AlertMessage.class);
            if (alert == null) {
                return;
            }
            Validator.testAlertDescription(i, AlertDescription.BAD_RECORD_MAC, alert);
        });
    }

    private AlertMessage tryToDecryptWithAppSecrets(TlsContext context, AbstractRecord record) {
        try {
            KeySet keySet = KeySetGenerator.generateKeySet(context, ProtocolVersion.TLS13, Tls13KeySetType.APPLICATION_TRAFFIC_SECRETS);
            RecordCipher recordCipher = RecordCipherFactory.getRecordCipher(context, keySet, context.getSelectedCipherSuite());
            RecordDecryptor dec = new RecordDecryptor(recordCipher, context);
            dec.decrypt(record);
            AlertHandler handler = new AlertHandler(context);
            AlertMessage alert = (AlertMessage) handler.parseMessage(record.getCleanProtocolMessageBytes().getValue(), 0, true).getMessage();
            return alert;
        } catch (Exception ex) {
            return null;
        }
    }
}
