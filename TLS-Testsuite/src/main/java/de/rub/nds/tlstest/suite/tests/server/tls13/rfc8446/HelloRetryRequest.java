package de.rub.nds.tlstest.suite.tests.server.tls13.rfc8446;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SupportedVersionsExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.MethodCondition;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.ScopeLimitations;
import de.rub.nds.tlstest.framework.annotations.ServerTest;
import de.rub.nds.tlstest.framework.annotations.TestDescription;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.annotations.categories.AlertCategory;
import de.rub.nds.tlstest.framework.annotations.categories.ComplianceCategory;
import de.rub.nds.tlstest.framework.annotations.categories.CryptoCategory;
import de.rub.nds.tlstest.framework.annotations.categories.DeprecatedFeatureCategory;
import de.rub.nds.tlstest.framework.annotations.categories.HandshakeCategory;
import de.rub.nds.tlstest.framework.annotations.categories.InteroperabilityCategory;
import de.rub.nds.tlstest.framework.annotations.categories.MessageStructureCategory;
import de.rub.nds.tlstest.framework.annotations.categories.SecurityCategory;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.DerivationType;
import de.rub.nds.tlstest.framework.model.derivationParameter.CipherSuiteDerivation;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
import de.rub.nds.tlstest.suite.tests.both.tls13.rfc8446.SharedExtensionTests;
import java.util.Arrays;
import java.util.LinkedList;
import static org.junit.Assert.assertTrue;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@ServerTest
@RFC(number = 8446, section = "4.1.4 Hello Retry Request")
public class HelloRetryRequest extends Tls13Test {
    
    public ConditionEvaluationResult sendsHelloRetryRequestForEmptyKeyShare() {
        if (context.getSiteReport().getResult(TlsAnalyzedProperty.SENDS_HELLO_RETRY_REQUEST) == TestResults.TRUE) {
            return ConditionEvaluationResult.enabled("");
        }
        return ConditionEvaluationResult.disabled("Target does not send a Hello Retry Request");
    }

    @TlsTest(description = "The server will send this message in response to a ClientHello "
            + "message if it is able to find an acceptable set of parameters but the "
            + "ClientHello does not contain sufficient information to proceed with "
            + "the handshake. [...]"
            + "The server's extensions MUST contain \"supported_versions\". [...]"
            + "\"supported_versions\" is REQUIRED for all ClientHello, ServerHello, and HelloRetryRequest messages.")
    @RFC(number = 8446, section = "4.1.4 Hello Retry Request and 9.2.  Mandatory-to-Implement Extensions")
    @InteroperabilityCategory(SeverityLevel.HIGH)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    @MethodCondition(method = "sendsHelloRetryRequestForEmptyKeyShare")
    @Tag("adjusted")
    public void helloRetryRequestValid(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        CipherSuite selectedCipher = derivationContainer.getDerivation(CipherSuiteDerivation.class).getSelectedValue();

        //4.2.8 Key Share: "This vector MAY be empty if the client is requesting a HelloRetryRequest."
        c.setDefaultClientKeyShareNamedGroups(new LinkedList<>());

        WorkflowTrace workflowTrace = runner.generateWorkflowTraceUntilReceivingMessage(WorkflowTraceType.HELLO, HandshakeMessageType.ENCRYPTED_EXTENSIONS);

        runner.execute(workflowTrace, c).validateFinal(i -> {
            Validator.executedAsPlanned(i);

            ServerHelloMessage sHello = (ServerHelloMessage) WorkflowTraceUtil.getFirstReceivedMessage(HandshakeMessageType.SERVER_HELLO, i.getWorkflowTrace());
            ClientHelloMessage cHello = i.getWorkflowTrace().getFirstSendMessage(ClientHelloMessage.class);
            if (sHello != null) {
                assertTrue("Server did not send a HelloRetryRequest", sHello.isTls13HelloRetryRequest());
                assertTrue("Server selected an unproposed CipherSuite", Arrays.equals(selectedCipher.getByteValue(), sHello.getSelectedCipherSuite().getValue()));
                assertTrue("Server did not include a SupportedVersions Extension", sHello.containsExtension(ExtensionType.SUPPORTED_VERSIONS));
                SharedExtensionTests.checkForDuplicateExtensions(sHello);
                ServerHello.checkForForbiddenExtensions(sHello);
                ServerHello.checkForUnproposedExtensions(sHello, cHello);
                KeyShareExtensionMessage ksExtension = sHello.getExtension(KeyShareExtensionMessage.class);
                if (ksExtension != null) {
                    assertTrue("Server did not include exactly one NamedGroup in KeyShare Extension", ksExtension.getKeyShareList().size() == 1);
                    assertTrue("Server included a public key in HelloRetryRequest", ksExtension.getKeyShareList().get(0).getPublicKey() == null);
                    assertTrue("Server selected an unproposed NamedGroup", c.getDefaultClientNamedGroups().contains(ksExtension.getKeyShareList().get(0).getGroupConfig()));
                }
            }
        });
    }
    
    @TlsTest(description = "Servers MUST ensure that they negotiate the "
            + "same cipher suite when receiving a conformant updated ClientHello")
    @RFC(number = 8446, section = "4.2.10 Early Data Indication")
    @ScopeLimitations(DerivationType.CIPHERSUITE)
    @InteroperabilityCategory(SeverityLevel.HIGH)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    @SecurityCategory(SeverityLevel.MEDIUM)
    @MethodCondition(method = "sendsHelloRetryRequestForEmptyKeyShare")
    public void selectsSameCipherSuiteAllAtOnce(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        c.setDefaultClientSupportedCipherSuites(new LinkedList<>(context.getSiteReport().getSupportedTls13CipherSuites()));
        WorkflowTrace workflowTrace = getHelloRetryWorkflowTrace(runner);
        
        runner.execute(workflowTrace, c).validateFinal(i -> {
            Validator.executedAsPlanned(i);

            ServerHelloMessage helloRetryRequest = (ServerHelloMessage) WorkflowTraceUtil.getFirstReceivedMessage(HandshakeMessageType.SERVER_HELLO, i.getWorkflowTrace());
            ServerHelloMessage actualServerHello = (ServerHelloMessage) WorkflowTraceUtil.getLastReceivedMessage(HandshakeMessageType.SERVER_HELLO, i.getWorkflowTrace());
            if (helloRetryRequest != null && actualServerHello != null) {
                assertTrue("Server selected an unproposed CipherSuite in HelloRetryRequest", context.getSiteReport().getSupportedTls13CipherSuites().contains(CipherSuite.getCipherSuite(helloRetryRequest.getSelectedCipherSuite().getValue())));
                assertTrue("Server selected a different CipherSuite in ServerHello than in HelloRetryRequest", Arrays.equals(helloRetryRequest.getSelectedCipherSuite().getValue(), actualServerHello.getSelectedCipherSuite().getValue()));
            }
        });
    }

    @TlsTest(description = "Servers MUST ensure that they negotiate the "
            + "same cipher suite when receiving a conformant updated ClientHello")
    @InteroperabilityCategory(SeverityLevel.HIGH)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    @SecurityCategory(SeverityLevel.MEDIUM)
    @MethodCondition(method = "sendsHelloRetryRequestForEmptyKeyShare")
    public void selectsSameCipherSuite(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        CipherSuite selectedCipherSuite = derivationContainer.getDerivation(CipherSuiteDerivation.class).getSelectedValue();

        WorkflowTrace workflowTrace = getHelloRetryWorkflowTrace(runner);

        runner.execute(workflowTrace, c).validateFinal(i -> {
            Validator.executedAsPlanned(i);

            ServerHelloMessage helloRetryRequest = (ServerHelloMessage) WorkflowTraceUtil.getFirstReceivedMessage(HandshakeMessageType.SERVER_HELLO, i.getWorkflowTrace());
            ServerHelloMessage actualServerHello = (ServerHelloMessage) WorkflowTraceUtil.getLastReceivedMessage(HandshakeMessageType.SERVER_HELLO, i.getWorkflowTrace());
            if (helloRetryRequest != null && actualServerHello != null) {
                assertTrue("Server selected an unproposed CipherSuite in HelloRetryRequest", Arrays.equals(helloRetryRequest.getSelectedCipherSuite().getValue(), selectedCipherSuite.getByteValue()));
                assertTrue("Server selected a different CipherSuite in ServerHello than in HelloRetryRequest", Arrays.equals(helloRetryRequest.getSelectedCipherSuite().getValue(), actualServerHello.getSelectedCipherSuite().getValue()));
            }
        });
    }
    
    @TlsTest(description = "The value of selected_version in the HelloRetryRequest " +
            "\"supported_versions\" extension MUST be retained in the ServerHello")
    @InteroperabilityCategory(SeverityLevel.HIGH)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    @SecurityCategory(SeverityLevel.MEDIUM)
    @MethodCondition(method = "sendsHelloRetryRequestForEmptyKeyShare")
    @Tag("new")
    public void retainsProtocolVersion(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        WorkflowTrace workflowTrace = getHelloRetryWorkflowTrace(runner);

        runner.execute(workflowTrace, c).validateFinal(i -> {
            Validator.executedAsPlanned(i);

            ServerHelloMessage helloRetryRequest = (ServerHelloMessage) WorkflowTraceUtil.getFirstReceivedMessage(HandshakeMessageType.SERVER_HELLO, i.getWorkflowTrace());
            ServerHelloMessage actualServerHello = (ServerHelloMessage) WorkflowTraceUtil.getLastReceivedMessage(HandshakeMessageType.SERVER_HELLO, i.getWorkflowTrace());
            if (helloRetryRequest != null && actualServerHello != null) {
                assertTrue("Server did not retain the selected Protocol Version in Supported Versions Extension", Arrays.equals(helloRetryRequest.getExtension(SupportedVersionsExtensionMessage.class).getSupportedVersions().getValue(), actualServerHello.getExtension(SupportedVersionsExtensionMessage.class).getSupportedVersions().getValue()));
            }
        });
    }
    
    @Test
    /*
    Clients MAY send an empty client_shares vector in order to request
    group selection from the server, at the cost of an additional round
    trip
    */
    @RFC(number = 8446, section = "4.1.1 Cryptographic Negotiation and 4.2.8.  Key Share")
    @TestDescription("If the server selects an (EC)DHE group and the client did not offer a " +
        "compatible \"key_share\" extension in the initial ClientHello, the " +
        "server MUST respond with a HelloRetryRequest (Section 4.1.4) message. " + 
        "[...] Clients MAY send an empty client_shares vector in order to request " +
        "group selection from the server, at the cost of an additional round " +
        "trip")
    @ComplianceCategory(SeverityLevel.HIGH)
    @InteroperabilityCategory(SeverityLevel.LOW)
    public void sentHelloRetryRequest() {
        assertTrue("No Hello Retry Request received by Scanner", context.getSiteReport().getResult(TlsAnalyzedProperty.SENDS_HELLO_RETRY_REQUEST) == TestResults.TRUE);
    }
    
    private WorkflowTrace getHelloRetryWorkflowTrace(WorkflowRunner runner) {
        WorkflowTrace workflowTrace = runner.generateWorkflowTraceUntilReceivingMessage(WorkflowTraceType.HELLO, HandshakeMessageType.ENCRYPTED_EXTENSIONS);
        ClientHelloMessage initialHello = (ClientHelloMessage) WorkflowTraceUtil.getFirstSendMessage(HandshakeMessageType.CLIENT_HELLO, workflowTrace);
        KeyShareExtensionMessage ksExt = initialHello.getExtension(KeyShareExtensionMessage.class);
        ksExt.setKeyShareListBytes(Modifiable.explicit(new byte[0]));

        if(context.getSiteReport().getResult(TlsAnalyzedProperty.ISSUES_COOKIE_IN_HELLO_RETRY) == TestResults.TRUE) {
           runner.getPreparedConfig().setAddCookieExtension(Boolean.TRUE); 
        }
        WorkflowTrace secondHelloTrace = runner.generateWorkflowTraceUntilSendingMessage(WorkflowTraceType.HANDSHAKE, HandshakeMessageType.FINISHED);
        
        //we usually use random values for client randoms but the 2nd hello
        //after an HRR must retain the random value from before
        byte[] fixedRandom = runner.getPreparedConfig().getDefaultClientRandom();
        initialHello.setRandom(Modifiable.explicit(fixedRandom));
        secondHelloTrace.getFirstSendMessage(ClientHelloMessage.class).setRandom(Modifiable.explicit(fixedRandom));
        
        workflowTrace.addTlsActions(secondHelloTrace.getTlsActions());
        return workflowTrace;
    }
}
