/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.client.tls13.rfc8446;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.EncryptedExtensionsMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PaddingExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.ClientTest;
import de.rub.nds.tlstest.framework.annotations.DynamicValueConstraints;
import de.rub.nds.tlstest.framework.annotations.ExplicitValues;
import de.rub.nds.tlstest.framework.annotations.MethodCondition;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.ScopeExtensions;
import de.rub.nds.tlstest.framework.annotations.ScopeLimitations;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.annotations.categories.Interoperability;
import de.rub.nds.tlstest.framework.annotations.categories.Security;
import de.rub.nds.tlstest.framework.coffee4j.model.ModelFromScope;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.DerivationType;
import de.rub.nds.tlstest.framework.model.ModelType;
import de.rub.nds.tlstest.framework.model.derivationParameter.CipherSuiteDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.DerivationParameter;
import de.rub.nds.tlstest.framework.model.derivationParameter.NamedGroupDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.mirrored.MirroredCipherSuiteDerivation;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
import de.rub.nds.tlstest.suite.tests.client.tls13.rfc8701.ServerInitiatedExtensionPoints;
import java.util.LinkedList;
import java.util.List;
import static org.junit.Assert.assertFalse;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@ClientTest
@RFC(number = 8446, section = "4.1.4 Hello Retry Request")
public class HelloRetryRequest extends Tls13Test {

    public List<DerivationParameter> getUnofferedGroups() {
        List<DerivationParameter> parameterValues = new LinkedList<>();
        List<NamedGroup> offeredGroups = context.getSiteReport().getClientHelloNamedGroups();
        NamedGroup.getImplemented().stream().filter(group -> !offeredGroups.contains(group))
                .forEach(unofferedGroup -> parameterValues.add(new NamedGroupDerivation(unofferedGroup)));
        return parameterValues;
    }

    @TlsTest(description = "Upon receipt of this extension in a HelloRetryRequest, the client "
            + "MUST verify that (1) the selected_group field corresponds to a group "
            + "which was provided in the \"supported_groups\" extension in the "
            + "original ClientHello and [...] If either of these checks fails, then "
            + "the client MUST abort the handshake with an \"illegal_parameter\" "
            + "alert.")
    @RFC(number = 8446, section = "4.2.8 Key Share")
    @Security(SeverityLevel.LOW)
    @ExplicitValues(affectedTypes = DerivationType.NAMED_GROUP, methods = "getUnofferedGroups")
    public void helloRetryRequestsUnofferedGroup(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        performHelloRetryRequestTest(argumentAccessor, runner);
    }

    public List<DerivationParameter> getUnofferedTls13CipherSuites() {
        List<DerivationParameter> parameterValues = new LinkedList<>();
        List<CipherSuite> offeredTls13 = CipherSuite.getCipherSuites(context.getReceivedClientHelloMessage().getCipherSuites().getValue());
        CipherSuite.getImplementedTls13CipherSuites().stream().filter(cipherSuite -> !offeredTls13.contains(cipherSuite))
                .forEach(cipherSuite -> parameterValues.add(new CipherSuiteDerivation(cipherSuite)));
        return parameterValues;
    }

    @TlsTest(description = "A client which receives a cipher suite that was not offered MUST "
            + "abort the handshake.")
    @ExplicitValues(affectedTypes = DerivationType.CIPHERSUITE, methods = "getUnofferedTls13CipherSuites")
    @Security(SeverityLevel.LOW)
    public void helloRetryRequestsUnofferedTls13CipherSuite(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        runner.setAutoHelloRetryRequest(false);
        NamedGroup selectedGroup = derivationContainer.getDerivation(NamedGroupDerivation.class).getSelectedValue();

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(new ReceiveAction(new AlertMessage()));
        runner.insertHelloRetryRequest(workflowTrace, selectedGroup);

        runner.execute(workflowTrace, c).validateFinal(i -> {
            Validator.receivedFatalAlert(i);
        });
    }

    public boolean isKeyShareInInitialHello(NamedGroup group) {
        return context.getSiteReport().getClientHelloKeyShareGroups().contains(group);
    }

    @TlsTest(description = "Clients MUST abort the handshake with an "
            + "\"illegal_parameter\" alert if the HelloRetryRequest would not result "
            + "in any change in the ClientHello.")
    @Security(SeverityLevel.LOW)
    @DynamicValueConstraints(affectedTypes = DerivationType.NAMED_GROUP, methods = "isKeyShareInInitialHello")
    public void helloRetryRequestResultsInNoChanges(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        performHelloRetryRequestTest(argumentAccessor, runner);
    }

    private void performHelloRetryRequestTest(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        runner.setAutoHelloRetryRequest(false);
        NamedGroup selectedGroup = derivationContainer.getDerivation(NamedGroupDerivation.class).getSelectedValue();

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(new ReceiveAction(new AlertMessage()));
        runner.insertHelloRetryRequest(workflowTrace, selectedGroup);

        runner.execute(workflowTrace, c).validateFinal(i -> {
            Validator.receivedFatalAlert(i);
            AlertMessage alert = i.getWorkflowTrace().getFirstReceivedMessage(AlertMessage.class);
            if (alert == null) {
                return;
            }
            Validator.testAlertDescription(i, AlertDescription.ILLEGAL_PARAMETER, alert);
        });
    }

    public boolean isNotKeyShareInInitialHello(NamedGroup group) {
        return !context.getSiteReport().getClientHelloKeyShareGroups().contains(group);
    }

    private NamedGroup getOtherSupportedNamedGroup(NamedGroup givenGroup) {
        for (NamedGroup group : context.getSiteReport().getSupportedTls13Groups()) {
            if (group != givenGroup) {
                return group;
            }
        }
        return null;
    }

    private ConditionEvaluationResult supportsMultipleNamedGroups() {
        if (context.getSiteReport().getSupportedTls13Groups().size() > 1) {
            return ConditionEvaluationResult.enabled("More than one NamedGroup supported by target in TLS 1.3");
        }
        return ConditionEvaluationResult.disabled("Target does not support more than one NamedGroup in TLS 1.3");
    }

    @TlsTest(description = "If a client receives a second "
            + "HelloRetryRequest in the same connection (i.e., where the ClientHello "
            + "was itself in response to a HelloRetryRequest), it MUST abort the "
            + "handshake with an \"unexpected_message\" alert.")
    @Interoperability(SeverityLevel.MEDIUM)
    @DynamicValueConstraints(affectedTypes = DerivationType.NAMED_GROUP, methods = "isNotKeyShareInInitialHello")
    @MethodCondition(method = "supportsMultipleNamedGroups")
    public void sendSecondHelloRetryRequest(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace workflowTrace = new WorkflowTrace();
        NamedGroup selectedGroup = derivationContainer.getDerivation(NamedGroupDerivation.class).getSelectedValue();
        //re-requesting the same group is covered by another testcase
        NamedGroup otherRequestableGroup = getOtherSupportedNamedGroup(selectedGroup);

        //first hello retry gets added by WorkflowRunner
        ServerHelloMessage secondHelloRetry = new ServerHelloMessage(c);
        secondHelloRetry.setRandom(Modifiable.explicit(ServerHelloMessage.getHelloRetryRequestRandom()));
        secondHelloRetry.getExtension(KeyShareExtensionMessage.class).setKeyShareListBytes(Modifiable.explicit(otherRequestableGroup.getValue()));

        workflowTrace.addTlsActions(
                new ReceiveAction(new ClientHelloMessage()),
                new SendAction(secondHelloRetry),
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(workflowTrace, c).validateFinal(i -> {
            assertFalse("Client replied to second HelloRetryRequest with ClientHello", WorkflowTraceUtil.getLastReceivedMessage(i.getWorkflowTrace()) instanceof ClientHelloMessage);
            Validator.receivedFatalAlert(i);
            AlertMessage alert = i.getWorkflowTrace().getFirstReceivedMessage(AlertMessage.class);
            if (alert == null) {
                return;
            }
            Validator.testAlertDescription(i, AlertDescription.UNEXPECTED_MESSAGE, alert);
        });
    }

    private ConditionEvaluationResult supportsMultipleCipherSuites() {
        if (context.getSiteReport().getSupportedTls13CipherSuites().size() > 1) {
            return ConditionEvaluationResult.enabled("More than one CipherSuite supported by target in TLS 1.3");
        }
        return ConditionEvaluationResult.disabled("Target does not support more than one CipherSuite in TLS 1.3");
    }

    @TlsTest(description = "Upon receiving "
            + "the ServerHello, clients MUST check that the cipher suite supplied in "
            + "the ServerHello is the same as that in the HelloRetryRequest and "
            + "otherwise abort the handshake with an \"illegal_parameter\" alert.")
    @Security(SeverityLevel.LOW)
    @ScopeExtensions(DerivationType.MIRRORED_CIPHERSUITE)
    @DynamicValueConstraints(affectedTypes = DerivationType.NAMED_GROUP, methods = "isNotKeyShareInInitialHello")
    @MethodCondition(method = "supportsMultipleCipherSuites")
    public void cipherSuiteDisparity(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        runner.setAutoHelloRetryRequest(false);
        NamedGroup selectedGroup = derivationContainer.getDerivation(NamedGroupDerivation.class).getSelectedValue();
        CipherSuite helloRetryCipherSuite = derivationContainer.getDerivation(MirroredCipherSuiteDerivation.class).getSelectedValue();

        WorkflowTrace workflowTrace = runner.generateWorkflowTraceUntilReceivingMessage(WorkflowTraceType.HANDSHAKE, ProtocolMessageType.CHANGE_CIPHER_SPEC);

        workflowTrace.addTlsActions(new ReceiveAction(new AlertMessage()));
        runner.insertHelloRetryRequest(workflowTrace, selectedGroup);
        ServerHelloMessage helloRetryRequest = (ServerHelloMessage) WorkflowTraceUtil.getFirstSendMessage(HandshakeMessageType.SERVER_HELLO, workflowTrace);
        helloRetryRequest.setSelectedCipherSuite(Modifiable.explicit(helloRetryCipherSuite.getByteValue()));

        runner.execute(workflowTrace, c).validateFinal(i -> {
            Validator.receivedFatalAlert(i);
            AlertMessage alert = i.getWorkflowTrace().getFirstReceivedMessage(AlertMessage.class);
            if (alert == null) {
                return;
            }
            Validator.testAlertDescription(i, AlertDescription.ILLEGAL_PARAMETER, alert);
        });
    }
    
    
    @TlsTest(description = "A client which receives a legacy_session_id_echo " +
            "field that does not match what it sent in the ClientHello MUST " +
            "abort the handshake with an \"illegal_parameter\" alert.")
    @Interoperability(SeverityLevel.HIGH)
    @DynamicValueConstraints(affectedTypes = DerivationType.NAMED_GROUP, methods = "isNotKeyShareInInitialHello")
    public void helloRetryLegacySessionId(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = getSharedTestWorkflowTrace(argumentAccessor, runner);
        ServerHello.sharedSessionIdTest(workflowTrace, runner);
    }
    
    
    @TlsTest(description = "legacy_compression_method: A single byte which " +
            "MUST have the value 0.")
    @Interoperability(SeverityLevel.HIGH)
    @DynamicValueConstraints(affectedTypes = DerivationType.NAMED_GROUP, methods = "isNotKeyShareInInitialHello")
    public void helloRetryCompressionValue(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = getSharedTestWorkflowTrace(argumentAccessor, runner);
        ServerHello.sharedCompressionValueTest(workflowTrace, runner);
    }
    
    @TlsTest(description = "Clients MUST reject GREASE values when negotiated by the server. " +
            "In particular, the client MUST fail the connection " +
            "if a GREASE value appears in any of the following: " +
            "The \"cipher_suite\" value in a ServerHello")
    @RFC(number = 8701, section = "4. Server-Initiated Extension Points")
    @Interoperability(SeverityLevel.HIGH)
    @ScopeExtensions(DerivationType.GREASE_CIPHERSUITE)
    @ScopeLimitations(DerivationType.CIPHERSUITE)
    @DynamicValueConstraints(affectedTypes = DerivationType.NAMED_GROUP, methods = "isNotKeyShareInInitialHello")
    public void helloRetryGreaseCipherSuite(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = getSharedTestWorkflowTrace(argumentAccessor, runner);
        ServerInitiatedExtensionPoints.sharedGreaseCipherSuiteTest(workflowTrace, runner, derivationContainer);
    }
    
    @TlsTest(description = "Clients MUST reject GREASE values when negotiated by the server. " +
            "In particular, the client MUST fail the connection " +
            "if a GREASE value appears in any of the following: " +
            "Any ServerHello extension")
    @RFC(number = 8701, section = "4. Server-Initiated Extension Points")
    @ModelFromScope(baseModel = ModelType.CERTIFICATE)
    @Interoperability(SeverityLevel.CRITICAL)
    @ScopeExtensions(DerivationType.GREASE_EXTENSION)
    @DynamicValueConstraints(affectedTypes = DerivationType.NAMED_GROUP, methods = "isNotKeyShareInInitialHello")
    public void helloRetryGreaseExtension(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = getSharedTestWorkflowTrace(argumentAccessor, runner);
        ServerInitiatedExtensionPoints.sharedServerHelloGreaseExtensionTest(workflowTrace, runner, derivationContainer);
    }
    
    
    @TlsTest(description = "Clients MUST reject GREASE values when negotiated by the server. " +
            "In particular, the client MUST fail the connection " +
            "if a GREASE value appears in any of the following: " +
            "The \"version\" value in a ServerHello or HelloRetryRequest")
    @RFC(number = 8701, section = "4. Server-Initiated Extension Points")
    @ModelFromScope(baseModel = ModelType.CERTIFICATE)
    @Interoperability(SeverityLevel.CRITICAL)
    @ScopeExtensions(DerivationType.GREASE_PROTOCOL_VERSION)
    @DynamicValueConstraints(affectedTypes = DerivationType.NAMED_GROUP, methods = "isNotKeyShareInInitialHello")
    public void helloRetryGreaseVersionSelected(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = getSharedTestWorkflowTrace(argumentAccessor, runner);
        ServerInitiatedExtensionPoints.sharedGreaseVersionTest(workflowTrace, runner, derivationContainer);
    }
    
    
    private WorkflowTrace getSharedTestWorkflowTrace(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        runner.setAutoHelloRetryRequest(false);
        NamedGroup selectedGroup = derivationContainer.getDerivation(NamedGroupDerivation.class).getSelectedValue();
        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));
        runner.insertHelloRetryRequest(workflowTrace, selectedGroup);
        
        return workflowTrace;
    }
}
