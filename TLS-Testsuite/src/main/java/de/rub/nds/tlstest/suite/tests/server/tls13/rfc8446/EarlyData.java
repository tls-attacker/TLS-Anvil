/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.server.tls13.rfc8446;

import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.DynamicValueConstraints;
import de.rub.nds.anvilcore.annotation.IncludeParameter;
import de.rub.nds.anvilcore.annotation.IncludeParameters;
import de.rub.nds.anvilcore.annotation.MethodCondition;
import de.rub.nds.anvilcore.annotation.ServerTest;
import de.rub.nds.anvilcore.teststate.AnvilTestCase;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.Tls13KeySetType;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.EncryptedExtensionsMessage;
import de.rub.nds.tlsattacker.core.protocol.message.EndOfEarlyDataMessage;
import de.rub.nds.tlsattacker.core.protocol.message.NewSessionTicketMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PreSharedKeyExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.psk.PskSet;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.RecordCryptoComputations;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipher;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipherFactory;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeyDerivator;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySet;
import de.rub.nds.tlsattacker.core.record.crypto.RecordDecryptor;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceConfigurationUtil;
import de.rub.nds.tlsattacker.core.workflow.action.GenericReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
import java.io.ByteArrayInputStream;
import java.util.List;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Tag;
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

    public ConditionEvaluationResult notSupports0rtt() {
        if (context.getFeatureExtractionResult().getResult(TlsAnalyzedProperty.SUPPORTS_TLS13_0_RTT)
                == TestResults.TRUE) {
            return ConditionEvaluationResult.disabled("Supports 0-RTT early data");
        }
        return ConditionEvaluationResult.enabled("");
    }

    public ConditionEvaluationResult sendsTicketsAndSupportsResumption() {
        if (context.getFeatureExtractionResult()
                        .getResult(TlsAnalyzedProperty.ISSUES_TLS13_SESSION_TICKETS_AFTER_HANDSHAKE)
                != TestResults.TRUE) {
            return ConditionEvaluationResult.disabled(
                    "Does not send TLS 1.3 session tickets after handshake");
        }

        if (context.getFeatureExtractionResult().getResult(TlsAnalyzedProperty.SUPPORTS_TLS13_PSK)
                        != TestResults.TRUE
                && context.getFeatureExtractionResult()
                                .getResult(TlsAnalyzedProperty.SUPPORTS_TLS13_PSK_DHE)
                        != TestResults.TRUE) {
            return ConditionEvaluationResult.disabled("Does not support TLS 1.3 PSK resumption");
        }

        return ConditionEvaluationResult.enabled("");
    }

    public ConditionEvaluationResult canTestEarlyDataRejection() {
        ConditionEvaluationResult zeroRttCondition = notSupports0rtt();
        return zeroRttCondition.isDisabled()
                ? zeroRttCondition
                : sendsTicketsAndSupportsResumption();
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
        workflowTrace.addTlsAction(new ReceiveAction(new ServerHelloMessage()));

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
        workflowTrace.addTlsAction(new ReceiveAction(new ServerHelloMessage()));

        ClientHelloMessage secondHello =
                (ClientHelloMessage)
                        WorkflowTraceConfigurationUtil.getLastStaticConfiguredSendMessage(
                                workflowTrace, HandshakeMessageType.CLIENT_HELLO);
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
        workflowTrace.addTlsAction(new ReceiveAction(new ServerHelloMessage()));

        ClientHelloMessage secondHello =
                (ClientHelloMessage)
                        WorkflowTraceConfigurationUtil.getLastStaticConfiguredSendMessage(
                                workflowTrace, HandshakeMessageType.CLIENT_HELLO);
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

    @AnvilTest(id = "8446-a55904e261")
    @Tag("rfc8446-coverage")
    @MethodCondition(method = "supports0rtt")
    public void sendEndOfEarlyUnprompted(AnvilTestCase testCase, WorkflowRunner runner) {
        // the RFC makes the end of early data an unexpected message by forbidding the client to
        // send it unprompted.
        // That forces the server to raise an unexpected_message alert
        //
        // The client side of this must statement is untestable.
        Config config = getPreparedConfig(runner);
        WorkflowTrace workflowTrace =
                runner.generateWorkflowTraceUntilSendingMessage(
                        WorkflowTraceType.HELLO, HandshakeMessageType.FINISHED);
        EndOfEarlyDataMessage endOfEarlyData = new EndOfEarlyDataMessage();
        endOfEarlyData.setAdjustContext(Modifiable.explicit(Boolean.FALSE));
        workflowTrace.addTlsAction(new SendAction(endOfEarlyData));
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));

        State state = runner.execute(workflowTrace, config);
        // check that the received EncryptedExtensions message does not contain the
        // early data extension
        WorkflowTrace trace = state.getWorkflowTrace();
        Assertions.assertFalse(
                trace.getLastReceivedMessage(EncryptedExtensionsMessage.class)
                        .containsExtension(ExtensionType.EARLY_DATA));
        // check that the server did not accept our unprompted EndOfEarlyData message
        // and aborted the connection
        Validator.receivedFatalAlert(state, testCase, AlertDescription.UNEXPECTED_MESSAGE);
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
        workflowTrace.addTlsAction(new ReceiveAction(new ServerHelloMessage()));

        SendAction cHello = (SendAction) workflowTrace.getLastSendingAction();
        cHello.getConfiguredMessages()
                .remove(
                        WorkflowTraceConfigurationUtil.getFirstStaticConfiguredSendMessage(
                                workflowTrace, ProtocolMessageType.APPLICATION_DATA));

        Record helloRecord = new Record();
        Record ccsCompatibilityRecord = new Record();
        Record earlyRecord = new Record();
        earlyRecord.setComputations(new RecordCryptoComputations());
        earlyRecord.getComputations().setCiphertext(Modifiable.xor(modificationBitmask, 0));

        ApplicationMessage earlyData = new ApplicationMessage();
        earlyData.setData(Modifiable.explicit(c.getDefaultApplicationMessageData().getBytes()));
        cHello.getConfiguredMessages().add(earlyData);

        ((SendAction) workflowTrace.getLastSendingAction()).getConfiguredRecords().add(helloRecord);
        if (c.getTls13BackwardsCompatibilityMode()) {
            ((SendAction) workflowTrace.getLastSendingAction())
                    .getConfiguredRecords()
                    .add(ccsCompatibilityRecord);
        }
        ((SendAction) workflowTrace.getLastSendingAction()).getConfiguredRecords().add(earlyRecord);

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
        Validator.testAlertDescription(state, testCase, AlertDescription.BAD_RECORD_MAC);
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
        workflowTrace.addTlsAction(new ReceiveAction(new ServerHelloMessage()));

        SendAction cHello = (SendAction) workflowTrace.getLastSendingAction();
        cHello.getConfiguredMessages()
                .remove(
                        WorkflowTraceConfigurationUtil.getFirstStaticConfiguredSendMessage(
                                workflowTrace, ProtocolMessageType.APPLICATION_DATA));

        Record helloRecord = new Record();
        Record ccsCompatibilityRecord = new Record();
        Record earlyRecord = new Record();
        earlyRecord.setComputations(new RecordCryptoComputations());
        earlyRecord.getComputations().setAuthenticationTag(Modifiable.xor(modificationBitmask, 0));

        ApplicationMessage earlyData = new ApplicationMessage();
        earlyData.setData(Modifiable.explicit("test".getBytes()));
        cHello.getConfiguredMessages().add(earlyData);

        ((SendAction) workflowTrace.getLastSendingAction()).getConfiguredRecords().add(helloRecord);
        if (c.getTls13BackwardsCompatibilityMode()) {
            ((SendAction) workflowTrace.getLastSendingAction())
                    .getConfiguredRecords()
                    .add(ccsCompatibilityRecord);
        }
        ((SendAction) workflowTrace.getLastSendingAction()).getConfiguredRecords().add(earlyRecord);

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
        Validator.testAlertDescription(state, testCase, AlertDescription.BAD_RECORD_MAC);
    }

    @AnvilTest(id = "8446-7cde05aa32")
    @Tag("rfc8446-coverage")
    @Tag("denies0rtt")
    @MethodCondition(method = "canTestEarlyDataRejection")
    public void denies0RTTwithHRR(AnvilTestCase testCase, WorkflowRunner runner) {
        // For this SUT, which does not support 0-RTT, only the rejection alternatives (option 1 and
        // 2) apply.
        Config ticketConfig = getConfig();
        ticketConfig.setAddPSKKeyExchangeModesExtension(true);
        runner.setPreparedConfig(ticketConfig);

        // First handshake to fetch a resumption ticket.
        WorkflowTrace ticketTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        ticketTrace.addTlsAction(new ReceiveAction(new NewSessionTicketMessage(false)));
        State ticketState = runner.execute(ticketTrace, ticketConfig);
        Validator.executedAsPlanned(ticketState, testCase);
        Assertions.assertNotNull(
                ticketTrace.getFirstReceivedMessage(NewSessionTicketMessage.class),
                "Server did not issue a ticket for the early-data attempt");
        List<PskSet> ticketPsks = ticketState.getTlsContext().getPskSets();
        Assertions.assertNotNull(ticketPsks, "No PSK derived from the server ticket");
        Assertions.assertFalse(ticketPsks.isEmpty(), "No PSK derived from the server ticket");

        // Second connection with early data
        Config c = getPreparedConfig(runner);
        c.setAddPSKKeyExchangeModesExtension(true);
        c.setDefaultPskSets(List.of(ticketPsks.get(0)));
        c.setAddPreSharedKeyExtension(true);
        c.setAddEarlyDataExtension(true);
        WorkflowTrace trace =
                runner.generateWorkflowTraceUntilLastReceivingMessage(
                        WorkflowTraceType.ZERO_RTT, HandshakeMessageType.SERVER_HELLO);
        trace.addTlsAction(new GenericReceiveAction());
        runner.execute(trace, c);

        ServerHelloMessage serverHello = trace.getLastReceivedMessage(ServerHelloMessage.class);
        Assertions.assertNotNull(serverHello, "Server did not respond to the ClientHello");
        // option 2: reject early data with HelloRetryRequest.
        //           This checks the response only, not the subsequent early-record skipping.
        if (serverHello.hasTls13HelloRetryRequestRandom()) {
            return;
        }

        // option 1: ignore early_data and return a regular 1-RTT response,
        //           without accepting early data via the EncryptedExtensions extension.
        EncryptedExtensionsMessage encryptedExtensions =
                trace.getLastReceivedMessage(EncryptedExtensionsMessage.class);
        Assertions.assertNotNull(encryptedExtensions, "Server did not send EncryptedExtensions");
        Assertions.assertFalse(
                encryptedExtensions.containsExtension(ExtensionType.EARLY_DATA),
                "Server accepted early data although it does not support 0-RTT");
    }

    private AlertMessage tryToDecryptWithAppSecrets(TlsContext context, Record record) {
        try {
            KeySet keySet =
                    KeyDerivator.generateKeySet(
                            context,
                            ProtocolVersion.TLS13,
                            Tls13KeySetType.APPLICATION_TRAFFIC_SECRETS);
            RecordCipher recordCipher = RecordCipherFactory.getRecordCipher(context, keySet, false);
            RecordDecryptor dec = new RecordDecryptor(recordCipher, context);
            dec.decrypt(record);
            AlertMessage alert = new AlertMessage();
            alert.getParser(
                            context.getContext(),
                            new ByteArrayInputStream(
                                    record.getCleanProtocolMessageBytes().getValue()))
                    .parse(alert);

            return alert;
        } catch (Exception ex) {
            return null;
        }
    }
}
