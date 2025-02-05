/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.server.tls13.rfc8446;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import de.rub.nds.anvilcore.annotation.*;
import de.rub.nds.anvilcore.teststate.AnvilTestCase;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SupportedVersionsExtensionMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceConfigurationUtil;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceResultUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.derivationParameter.CipherSuiteDerivation;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
import de.rub.nds.tlstest.suite.tests.both.tls13.rfc8446.SharedExtensionTests;
import java.util.Arrays;
import java.util.LinkedList;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;

@ServerTest
public class HelloRetryRequest extends Tls13Test {

    public ConditionEvaluationResult sendsHelloRetryRequestForEmptyKeyShare() {
        if (context.getFeatureExtractionResult()
                        .getResult(TlsAnalyzedProperty.SENDS_HELLO_RETRY_REQUEST)
                == TestResults.TRUE) {
            return ConditionEvaluationResult.enabled("");
        }
        return ConditionEvaluationResult.disabled("Target does not send a Hello Retry Request");
    }

    @AnvilTest(id = "8446-7STiGzfK9u")
    @MethodCondition(method = "sendsHelloRetryRequestForEmptyKeyShare")
    @Tag("adjusted")
    public void helloRetryRequestValid(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);
        CipherSuite selectedCipher =
                parameterCombination.getParameter(CipherSuiteDerivation.class).getSelectedValue();

        // 4.2.8 Key Share: "This vector MAY be empty if the client is requesting a
        // HelloRetryRequest."
        c.setDefaultClientKeyShareNamedGroups(new LinkedList<>());

        WorkflowTrace workflowTrace =
                runner.generateWorkflowTraceUntilReceivingMessage(
                        WorkflowTraceType.HELLO, HandshakeMessageType.ENCRYPTED_EXTENSIONS);

        State state = runner.execute(workflowTrace, c);

        Validator.executedAsPlanned(state, testCase);

        ServerHelloMessage sHello =
                (ServerHelloMessage)
                        WorkflowTraceResultUtil.getFirstReceivedMessage(
                                state.getWorkflowTrace(), HandshakeMessageType.SERVER_HELLO);
        ClientHelloMessage cHello =
                state.getWorkflowTrace().getFirstSentMessage(ClientHelloMessage.class);
        if (sHello != null) {
            assertTrue(
                    "Server did not send a HelloRetryRequest", sHello.isTls13HelloRetryRequest());
            assertTrue(
                    "Server selected an unproposed CipherSuite",
                    Arrays.equals(
                            selectedCipher.getByteValue(),
                            sHello.getSelectedCipherSuite().getValue()));
            assertTrue(
                    "Server did not include a SupportedVersions Extension",
                    sHello.containsExtension(ExtensionType.SUPPORTED_VERSIONS));
            SharedExtensionTests.checkForDuplicateExtensions(sHello);
            ServerHello.checkForForbiddenExtensions(sHello);
            ServerHello.checkForUnproposedExtensions(sHello, cHello);
            KeyShareExtensionMessage ksExtension =
                    sHello.getExtension(KeyShareExtensionMessage.class);
            if (ksExtension != null) {
                assertTrue(
                        "Server did not include exactly one NamedGroup in KeyShare Extension",
                        ksExtension.getKeyShareList().size() == 1);
                assertTrue(
                        "Server included a public key in HelloRetryRequest",
                        ksExtension.getKeyShareList().get(0).getPublicKey() == null);
                assertTrue(
                        "Server selected an unproposed NamedGroup",
                        c.getDefaultClientNamedGroups()
                                .contains(ksExtension.getKeyShareList().get(0).getGroupConfig()));
            }
        }
    }

    @AnvilTest(id = "8446-aVxixR6JLE")
    @ExcludeParameter("CIPHER_SUITE")
    @MethodCondition(method = "sendsHelloRetryRequestForEmptyKeyShare")
    public void selectsSameCipherSuiteAllAtOnce(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);
        c.setDefaultClientSupportedCipherSuites(
                new LinkedList<>(
                        context.getFeatureExtractionResult().getSupportedTls13CipherSuites()));
        WorkflowTrace workflowTrace = getHelloRetryWorkflowTrace(runner);

        State state = runner.execute(workflowTrace, c);

        Validator.executedAsPlanned(state, testCase);
        checkForDuplicateCcs(workflowTrace);

        ServerHelloMessage helloRetryRequest =
                (ServerHelloMessage)
                        WorkflowTraceResultUtil.getFirstReceivedMessage(
                                state.getWorkflowTrace(), HandshakeMessageType.SERVER_HELLO);
        ServerHelloMessage actualServerHello =
                (ServerHelloMessage)
                        WorkflowTraceResultUtil.getLastReceivedMessage(
                                state.getWorkflowTrace(), HandshakeMessageType.SERVER_HELLO);
        if (helloRetryRequest != null && actualServerHello != null) {
            assertTrue(
                    "Server selected an unproposed CipherSuite in HelloRetryRequest",
                    context.getFeatureExtractionResult()
                            .getSupportedTls13CipherSuites()
                            .contains(
                                    CipherSuite.getCipherSuite(
                                            helloRetryRequest
                                                    .getSelectedCipherSuite()
                                                    .getValue())));
            assertTrue(
                    "Server selected a different CipherSuite in ServerHello than in HelloRetryRequest",
                    Arrays.equals(
                            helloRetryRequest.getSelectedCipherSuite().getValue(),
                            actualServerHello.getSelectedCipherSuite().getValue()));
        }
    }

    @AnvilTest(id = "8446-PqtPy7dAY2")
    @MethodCondition(method = "sendsHelloRetryRequestForEmptyKeyShare")
    public void selectsSameCipherSuite(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);
        CipherSuite selectedCipherSuite =
                parameterCombination.getParameter(CipherSuiteDerivation.class).getSelectedValue();

        WorkflowTrace workflowTrace = getHelloRetryWorkflowTrace(runner);

        State state = runner.execute(workflowTrace, c);

        Validator.executedAsPlanned(state, testCase);
        checkForDuplicateCcs(workflowTrace);

        ServerHelloMessage helloRetryRequest =
                (ServerHelloMessage)
                        WorkflowTraceResultUtil.getFirstReceivedMessage(
                                state.getWorkflowTrace(), HandshakeMessageType.SERVER_HELLO);
        ServerHelloMessage actualServerHello =
                (ServerHelloMessage)
                        WorkflowTraceResultUtil.getLastReceivedMessage(
                                state.getWorkflowTrace(), HandshakeMessageType.SERVER_HELLO);
        if (helloRetryRequest != null && actualServerHello != null) {
            assertTrue(
                    "Server selected an unproposed CipherSuite in HelloRetryRequest",
                    Arrays.equals(
                            helloRetryRequest.getSelectedCipherSuite().getValue(),
                            selectedCipherSuite.getByteValue()));
            assertTrue(
                    "Server selected a different CipherSuite in ServerHello than in HelloRetryRequest",
                    Arrays.equals(
                            helloRetryRequest.getSelectedCipherSuite().getValue(),
                            actualServerHello.getSelectedCipherSuite().getValue()));
        }
    }

    @AnvilTest(id = "8446-i5qA9bNwto")
    @MethodCondition(method = "sendsHelloRetryRequestForEmptyKeyShare")
    @Tag("new")
    public void retainsProtocolVersion(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);

        WorkflowTrace workflowTrace = getHelloRetryWorkflowTrace(runner);

        State state = runner.execute(workflowTrace, c);

        Validator.executedAsPlanned(state, testCase);
        checkForDuplicateCcs(workflowTrace);

        ServerHelloMessage helloRetryRequest =
                (ServerHelloMessage)
                        WorkflowTraceResultUtil.getFirstReceivedMessage(
                                state.getWorkflowTrace(), HandshakeMessageType.SERVER_HELLO);
        ServerHelloMessage actualServerHello =
                (ServerHelloMessage)
                        WorkflowTraceResultUtil.getLastReceivedMessage(
                                state.getWorkflowTrace(), HandshakeMessageType.SERVER_HELLO);
        if (helloRetryRequest != null && actualServerHello != null) {
            assertTrue(
                    "Server did not retain the selected Protocol Version in Supported Versions Extension",
                    Arrays.equals(
                            helloRetryRequest
                                    .getExtension(SupportedVersionsExtensionMessage.class)
                                    .getSupportedVersions()
                                    .getValue(),
                            actualServerHello
                                    .getExtension(SupportedVersionsExtensionMessage.class)
                                    .getSupportedVersions()
                                    .getValue()));
        }
    }

    @NonCombinatorialAnvilTest(id = "8446-FwJUHPJFYr")
    /*
    Clients MAY send an empty client_shares vector in order to request
    group selection from the server, at the cost of an additional round
    trip
    */
    public void sentHelloRetryRequest() {
        assertTrue(
                "No Hello Retry Request received by Scanner",
                context.getFeatureExtractionResult()
                                .getResult(TlsAnalyzedProperty.SENDS_HELLO_RETRY_REQUEST)
                        == TestResults.TRUE);
    }

    private WorkflowTrace getHelloRetryWorkflowTrace(WorkflowRunner runner) {
        WorkflowTrace workflowTrace =
                runner.generateWorkflowTraceUntilReceivingMessage(
                        WorkflowTraceType.HELLO, HandshakeMessageType.ENCRYPTED_EXTENSIONS);
        ClientHelloMessage initialHello =
                (ClientHelloMessage)
                        WorkflowTraceConfigurationUtil.getFirstStaticConfiguredSendMessage(
                                workflowTrace, HandshakeMessageType.CLIENT_HELLO);
        KeyShareExtensionMessage ksExt = initialHello.getExtension(KeyShareExtensionMessage.class);
        ksExt.setKeyShareListBytes(Modifiable.explicit(new byte[0]));

        if (context.getFeatureExtractionResult()
                        .getResult(TlsAnalyzedProperty.ISSUES_COOKIE_IN_HELLO_RETRY)
                == TestResults.TRUE) {
            runner.getPreparedConfig().setAddCookieExtension(Boolean.TRUE);
        }
        WorkflowTrace secondHelloTrace =
                runner.generateWorkflowTraceUntilSendingMessage(
                        WorkflowTraceType.HANDSHAKE, HandshakeMessageType.FINISHED);

        // we usually use random values for client randoms but the 2nd hello
        // after an HRR must retain the random value from before
        byte[] fixedRandom = runner.getPreparedConfig().getDefaultClientRandom();
        initialHello.setRandom(Modifiable.explicit(fixedRandom));
        ((ClientHelloMessage)
                        WorkflowTraceConfigurationUtil.getFirstStaticConfiguredSendMessage(
                                secondHelloTrace, HandshakeMessageType.CLIENT_HELLO))
                .setRandom(Modifiable.explicit(fixedRandom));

        // In middlebox compatibility mode, a CCS message is sent
        // immediately after a ServerHello/HelloRetryRequest message. Since the
        // workflow trace considers the CCS message optional, it does not wait
        // for CCS before executing the SendAction. In this case, the CSS is received
        // in the second ReceiveAction. Therefore, an optional CCS option must be
        // allowed in the second receive action. A CCS message after the
        // second ServerHello is invalid, though.
        ChangeCipherSpecMessage optionalCCSMessage = new ChangeCipherSpecMessage();
        optionalCCSMessage.setRequired(false);

        ReceiveAction firstReceive = (ReceiveAction) secondHelloTrace.getFirstReceivingAction();
        firstReceive.getExpectedMessages().removeIf(msg -> msg instanceof ChangeCipherSpecMessage);
        firstReceive.getExpectedMessages().add(0, optionalCCSMessage);

        workflowTrace.addTlsActions(secondHelloTrace.getTlsActions());
        return workflowTrace;
    }

    private void checkForDuplicateCcs(WorkflowTrace executedTrace) {
        // due to our workflow structure, CCS may be parsed with the first ServerHello or before the
        // new
        // ServerHello but it must not be sent twice by the server
        assertFalse(
                "Received more than one compatibility CCS from Server",
                WorkflowTraceResultUtil.getAllReceivedMessagesOfType(
                                        executedTrace, ProtocolMessageType.CHANGE_CIPHER_SPEC)
                                .size()
                        > 1);
    }
}
