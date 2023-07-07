/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.client.tls13.rfc8446;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.DynamicValueConstraints;
import de.rub.nds.anvilcore.annotation.ExplicitValues;
import de.rub.nds.anvilcore.coffee4j.model.ModelFromScope;
import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.CookieExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SupportedVersionsExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareEntry;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.ClientFeatureExtractionResult;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.ClientTest;
import de.rub.nds.tlstest.framework.annotations.ManualConfig;
import de.rub.nds.tlstest.framework.annotations.MethodCondition;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.ScopeExtensions;
import de.rub.nds.tlstest.framework.annotations.ScopeLimitations;
import de.rub.nds.tlstest.framework.annotations.categories.AlertCategory;
import de.rub.nds.tlstest.framework.annotations.categories.ComplianceCategory;
import de.rub.nds.tlstest.framework.annotations.categories.DeprecatedFeatureCategory;
import de.rub.nds.tlstest.framework.annotations.categories.HandshakeCategory;
import de.rub.nds.tlstest.framework.annotations.categories.InteroperabilityCategory;
import de.rub.nds.tlstest.framework.annotations.categories.SecurityCategory;
import de.rub.nds.tlstest.framework.anvil.TlsAnvilConfig;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.TlsParameterType;
import de.rub.nds.tlstest.framework.model.derivationParameter.CipherSuiteDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.NamedGroupDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.mirrored.MirroredCipherSuiteDerivation;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
import de.rub.nds.tlstest.suite.tests.client.tls13.rfc8701.ServerInitiatedExtensionPoints;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@ClientTest
@RFC(number = 8446, section = "4.1.4 Hello Retry Request")
public class HelloRetryRequest extends Tls13Test {

    public List<DerivationParameter<TlsAnvilConfig, NamedGroup>> getUnofferedGroups(
            DerivationScope scope) {
        List<DerivationParameter<TlsAnvilConfig, NamedGroup>> parameterValues = new LinkedList<>();
        List<NamedGroup> offeredGroups =
                ((ClientFeatureExtractionResult) context.getFeatureExtractionResult())
                        .getClientHelloNamedGroups();
        NamedGroup.getImplemented().stream()
                .filter(group -> !offeredGroups.contains(group))
                .forEach(
                        unofferedGroup ->
                                parameterValues.add(new NamedGroupDerivation(unofferedGroup)));
        return parameterValues;
    }

    @AnvilTest(
            description =
                    "Upon receipt of this extension in a HelloRetryRequest, the client "
                            + "MUST verify that (1) the selected_group field corresponds to a group "
                            + "which was provided in the \"supported_groups\" extension in the "
                            + "original ClientHello and [...] If either of these checks fails, then "
                            + "the client MUST abort the handshake with an \"illegal_parameter\" "
                            + "alert.")
    @RFC(number = 8446, section = "4.2.8 Key Share")
    @ExplicitValues(affectedIdentifiers = "NAMED_GROUP", methods = "getUnofferedGroups")
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.MEDIUM)
    public void helloRetryRequestsUnofferedGroup(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        performHelloRetryRequestTest(argumentAccessor, runner);
    }

    public List<DerivationParameter> getUnofferedTls13CipherSuites(DerivationScope scope) {
        List<DerivationParameter> parameterValues = new LinkedList<>();
        List<CipherSuite> offeredTls13 =
                CipherSuite.getCipherSuites(
                        context.getReceivedClientHelloMessage().getCipherSuites().getValue());
        CipherSuite.getImplementedTls13CipherSuites().stream()
                .filter(cipherSuite -> !offeredTls13.contains(cipherSuite))
                .forEach(
                        cipherSuite -> parameterValues.add(new CipherSuiteDerivation(cipherSuite)));
        return parameterValues;
    }

    @AnvilTest(
            description =
                    "A client which receives a cipher suite that was not offered MUST "
                            + "abort the handshake.")
    @ExplicitValues(affectedIdentifiers = "CIPHER_SUITE", methods = "getUnofferedTls13CipherSuites")
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.LOW)
    @ComplianceCategory(SeverityLevel.MEDIUM)
    public void helloRetryRequestsUnofferedTls13CipherSuite(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        runner.setAutoHelloRetryRequest(false);
        NamedGroup selectedGroup =
                derivationContainer.getDerivation(NamedGroupDerivation.class).getSelectedValue();

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(new ReceiveAction(new AlertMessage()));
        runner.insertHelloRetryRequest(workflowTrace, selectedGroup);

        runner.execute(workflowTrace, c)
                .validateFinal(
                        i -> {
                            Validator.receivedFatalAlert(i);
                            AlertMessage alert =
                                    i.getWorkflowTrace()
                                            .getFirstReceivedMessage(AlertMessage.class);
                            // illegal parameter is not mentioned in the quote above but is
                            // mandatory
                            // for the ServerHello case
                            Validator.testAlertDescription(
                                    i, AlertDescription.ILLEGAL_PARAMETER, alert);
                        });
    }

    public boolean isKeyShareInInitialHello(NamedGroup group) {
        return ((ClientFeatureExtractionResult) context.getFeatureExtractionResult())
                .getClientHelloKeyShareGroups()
                .contains(group);
    }

    @AnvilTest(
            description =
                    "Clients MUST abort the handshake with an "
                            + "\"illegal_parameter\" alert if the HelloRetryRequest would not result "
                            + "in any change in the ClientHello.")
    @DynamicValueConstraints(
            affectedIdentifiers = "NAMED_GROUP",
            methods = "isKeyShareInInitialHello")
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.MEDIUM)
    public void helloRetryRequestResultsInNoChanges(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        performHelloRetryRequestTest(argumentAccessor, runner);
    }

    private void performHelloRetryRequestTest(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        runner.setAutoHelloRetryRequest(false);
        NamedGroup selectedGroup =
                derivationContainer.getDerivation(NamedGroupDerivation.class).getSelectedValue();

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(new ReceiveAction(new AlertMessage()));
        runner.insertHelloRetryRequest(workflowTrace, selectedGroup);

        runner.execute(workflowTrace, c)
                .validateFinal(
                        i -> {
                            Validator.receivedFatalAlert(i);
                            AlertMessage alert =
                                    i.getWorkflowTrace()
                                            .getFirstReceivedMessage(AlertMessage.class);
                            Validator.testAlertDescription(
                                    i, AlertDescription.ILLEGAL_PARAMETER, alert);
                        });
    }

    public boolean isNotKeyShareInInitialHello(NamedGroup group) {
        return !((ClientFeatureExtractionResult) context.getFeatureExtractionResult())
                .getClientHelloKeyShareGroups()
                .contains(group);
    }

    private NamedGroup getOtherSupportedNamedGroup(NamedGroup givenGroup) {
        for (NamedGroup group : context.getFeatureExtractionResult().getTls13Groups()) {
            if (group != givenGroup) {
                return group;
            }
        }
        return null;
    }

    public ConditionEvaluationResult supportsMultipleNamedGroups() {
        if (context.getFeatureExtractionResult().getTls13Groups().size() > 1) {
            return ConditionEvaluationResult.enabled(
                    "More than one NamedGroup supported by target in TLS 1.3");
        }
        return ConditionEvaluationResult.disabled(
                "Target does not support more than one NamedGroup in TLS 1.3");
    }

    @AnvilTest(
            description =
                    "If a client receives a second "
                            + "HelloRetryRequest in the same connection (i.e., where the ClientHello "
                            + "was itself in response to a HelloRetryRequest), it MUST abort the "
                            + "handshake with an \"unexpected_message\" alert.")
    @DynamicValueConstraints(
            affectedIdentifiers = "NAMED_GROUP",
            methods = "isNotKeyShareInInitialHello")
    @MethodCondition(method = "supportsMultipleNamedGroups")
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    public void sendSecondHelloRetryRequest(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace workflowTrace = new WorkflowTrace();
        NamedGroup selectedGroup =
                derivationContainer.getDerivation(NamedGroupDerivation.class).getSelectedValue();
        // re-requesting the same group is covered by another testcase
        NamedGroup otherRequestableGroup = getOtherSupportedNamedGroup(selectedGroup);

        // first hello retry gets added by WorkflowRunner
        ServerHelloMessage secondHelloRetry = new ServerHelloMessage(c);
        secondHelloRetry.setRandom(
                Modifiable.explicit(ServerHelloMessage.getHelloRetryRequestRandom()));
        secondHelloRetry
                .getExtension(KeyShareExtensionMessage.class)
                .setKeyShareListBytes(Modifiable.explicit(otherRequestableGroup.getValue()));

        workflowTrace.addTlsActions(
                new ReceiveAction(new ClientHelloMessage()),
                new SendAction(secondHelloRetry),
                new ReceiveAction(new AlertMessage()));

        runner.execute(workflowTrace, c)
                .validateFinal(
                        i -> {
                            assertFalse(
                                    "Client replied to second HelloRetryRequest with ClientHello",
                                    WorkflowTraceUtil.getLastReceivedMessage(i.getWorkflowTrace())
                                                    instanceof ClientHelloMessage
                                            && i.getWorkflowTrace()
                                                            .getLastReceivingAction()
                                                            .getReceivedMessages()
                                                    != null
                                            && i.getWorkflowTrace()
                                                    .getLastReceivingAction()
                                                    .getReceivedMessages()
                                                    .contains(
                                                            WorkflowTraceUtil
                                                                    .getLastReceivedMessage(
                                                                            i.getWorkflowTrace())));
                            Validator.receivedFatalAlert(i);
                            AlertMessage alert =
                                    i.getWorkflowTrace()
                                            .getFirstReceivedMessage(AlertMessage.class);
                            Validator.testAlertDescription(
                                    i, AlertDescription.UNEXPECTED_MESSAGE, alert);
                        });
    }

    private ConditionEvaluationResult supportsMultipleCipherSuites() {
        if (context.getFeatureExtractionResult().getSupportedTls13CipherSuites().size() > 1) {
            return ConditionEvaluationResult.enabled(
                    "More than one CipherSuite supported by target in TLS 1.3");
        }
        return ConditionEvaluationResult.disabled(
                "Target does not support more than one CipherSuite in TLS 1.3");
    }

    @AnvilTest(
            description =
                    "Upon receiving "
                            + "the ServerHello, clients MUST check that the cipher suite supplied in "
                            + "the ServerHello is the same as that in the HelloRetryRequest and "
                            + "otherwise abort the handshake with an \"illegal_parameter\" alert.")
    @ScopeExtensions(TlsParameterType.MIRRORED_CIPHERSUITE)
    @DynamicValueConstraints(
            affectedIdentifiers = "NAMED_GROUP",
            methods = "isNotKeyShareInInitialHello")
    @MethodCondition(method = "supportsMultipleCipherSuites")
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    public void cipherSuiteDisparity(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        runner.setAutoHelloRetryRequest(false);
        NamedGroup selectedGroup =
                derivationContainer.getDerivation(NamedGroupDerivation.class).getSelectedValue();
        CipherSuite helloRetryCipherSuite =
                derivationContainer
                        .getDerivation(MirroredCipherSuiteDerivation.class)
                        .getSelectedValue();

        WorkflowTrace workflowTrace =
                runner.generateWorkflowTraceUntilReceivingMessage(
                        WorkflowTraceType.HANDSHAKE, ProtocolMessageType.CHANGE_CIPHER_SPEC);

        workflowTrace.addTlsActions(new ReceiveAction(new AlertMessage()));
        runner.insertHelloRetryRequest(workflowTrace, selectedGroup);
        ServerHelloMessage helloRetryRequest =
                (ServerHelloMessage)
                        WorkflowTraceUtil.getFirstSendMessage(
                                HandshakeMessageType.SERVER_HELLO, workflowTrace);
        helloRetryRequest.setSelectedCipherSuite(
                Modifiable.explicit(helloRetryCipherSuite.getByteValue()));

        runner.execute(workflowTrace, c)
                .validateFinal(
                        i -> {
                            Validator.receivedFatalAlert(i);
                            AlertMessage alert =
                                    i.getWorkflowTrace()
                                            .getFirstReceivedMessage(AlertMessage.class);
                            Validator.testAlertDescription(
                                    i, AlertDescription.ILLEGAL_PARAMETER, alert);
                        });
    }

    @AnvilTest(
            description =
                    "If using "
                            + "(EC)DHE key establishment and a HelloRetryRequest containing a "
                            + "\"key_share\" extension was received by the client, the client MUST "
                            + "verify that the selected NamedGroup in the ServerHello is the same as "
                            + "that in the HelloRetryRequest.  If this check fails, the client MUST "
                            + "abort the handshake with an \"illegal_parameter\" alert.")
    @RFC(number = 8446, section = "4.2.8.  Key Share")
    @ScopeExtensions(TlsParameterType.MIRRORED_CIPHERSUITE)
    @DynamicValueConstraints(
            affectedIdentifiers = "NAMED_GROUP",
            methods = "isNotKeyShareInInitialHello")
    @ManualConfig(TlsParameterType.NAMED_GROUP)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    @Tag("new")
    public void namedGroupDisparity(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        runner.setAutoHelloRetryRequest(false);
        NamedGroup actualHelloGroup =
                ((ClientFeatureExtractionResult) context.getFeatureExtractionResult())
                        .getClientHelloNamedGroups()
                        .get(0);
        config.setDefaultServerNamedGroups(actualHelloGroup);
        config.setDefaultSelectedNamedGroup(actualHelloGroup);

        NamedGroup hrrNamedGroup =
                derivationContainer.getDerivation(NamedGroupDerivation.class).getSelectedValue();
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.SHORT_HELLO);
        runner.insertHelloRetryRequest(workflowTrace, hrrNamedGroup);
        workflowTrace.addTlsActions(new ReceiveAction(new AlertMessage()));

        runner.execute(workflowTrace, config)
                .validateFinal(
                        i -> {
                            Validator.receivedFatalAlert(i);
                            AlertMessage alert =
                                    i.getWorkflowTrace()
                                            .getFirstReceivedMessage(AlertMessage.class);
                            Validator.testAlertDescription(
                                    i, AlertDescription.ILLEGAL_PARAMETER, alert);
                        });
    }

    @AnvilTest(
            description =
                    "The value of selected_version in the HelloRetryRequest "
                            + "\"supported_versions\" extension MUST be retained in the ServerHello, "
                            + "and a client MUST abort the handshake with an \"illegal_parameter\" "
                            + "alert if the value changes.")
    @ScopeExtensions(TlsParameterType.MIRRORED_CIPHERSUITE)
    @DynamicValueConstraints(
            affectedIdentifiers = "NAMED_GROUP",
            methods = "isNotKeyShareInInitialHello")
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    @Tag("new")
    public void versionDisparity(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        runner.setAutoHelloRetryRequest(false);
        NamedGroup selectedGroup =
                derivationContainer.getDerivation(NamedGroupDerivation.class).getSelectedValue();

        WorkflowTrace workflowTrace =
                runner.generateWorkflowTraceUntilSendingMessage(
                        WorkflowTraceType.HELLO, HandshakeMessageType.SERVER_HELLO);
        runner.insertHelloRetryRequest(workflowTrace, selectedGroup);
        ServerHelloMessage modifiedServerHello = new ServerHelloMessage(config);
        workflowTrace.addTlsAction(new SendAction(modifiedServerHello));
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));

        SupportedVersionsExtensionMessage supportedVersions =
                modifiedServerHello.getExtension(SupportedVersionsExtensionMessage.class);
        supportedVersions.setSupportedVersions(Modifiable.explicit(new byte[] {03, 05}));

        runner.execute(workflowTrace, config)
                .validateFinal(
                        i -> {
                            Validator.receivedFatalAlert(i);
                            AlertMessage alert =
                                    i.getWorkflowTrace()
                                            .getFirstReceivedMessage(AlertMessage.class);
                            Validator.testAlertDescription(
                                    i, AlertDescription.ILLEGAL_PARAMETER, alert);
                        });
    }

    @AnvilTest(
            description =
                    "A client which receives a legacy_session_id_echo "
                            + "field that does not match what it sent in the ClientHello MUST "
                            + "abort the handshake with an \"illegal_parameter\" alert.")
    @DynamicValueConstraints(
            affectedIdentifiers = "NAMED_GROUP",
            methods = "isNotKeyShareInInitialHello")
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    public void helloRetryLegacySessionId(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = getSharedTestWorkflowTrace(argumentAccessor, runner);
        ServerHello.sharedSessionIdTest(workflowTrace, runner);
    }

    @AnvilTest(
            description =
                    "legacy_compression_method: A single byte which " + "MUST have the value 0.")
    @DynamicValueConstraints(
            affectedIdentifiers = "NAMED_GROUP",
            methods = "isNotKeyShareInInitialHello")
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.MEDIUM)
    @DeprecatedFeatureCategory(SeverityLevel.HIGH)
    public void helloRetryCompressionValue(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = getSharedTestWorkflowTrace(argumentAccessor, runner);
        ServerHello.sharedCompressionValueTest(workflowTrace, runner);
    }

    @AnvilTest(
            description =
                    "Clients MUST reject GREASE values when negotiated by the server. "
                            + "In particular, the client MUST fail the connection "
                            + "if a GREASE value appears in any of the following: "
                            + "[...] The \"cipher_suite\" value in a ServerHello")
    @RFC(number = 8701, section = "4. Server-Initiated Extension Points")
    @ScopeExtensions(TlsParameterType.GREASE_CIPHERSUITE)
    @ScopeLimitations(TlsParameterType.CIPHER_SUITE)
    @DynamicValueConstraints(
            affectedIdentifiers = "NAMED_GROUP",
            methods = "isNotKeyShareInInitialHello")
    @ComplianceCategory(SeverityLevel.MEDIUM)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    public void helloRetryGreaseCipherSuite(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = getSharedTestWorkflowTrace(argumentAccessor, runner);
        ServerInitiatedExtensionPoints.sharedGreaseCipherSuiteTest(
                workflowTrace, runner, derivationContainer);
    }

    @AnvilTest(
            description =
                    "Clients MUST reject GREASE values when negotiated by the server. "
                            + "In particular, the client MUST fail the connection "
                            + "if a GREASE value appears in any of the following: "
                            + "[...] Any ServerHello extension")
    @RFC(number = 8701, section = "4. Server-Initiated Extension Points")
    @ModelFromScope(modelType = "CERTIFICATE")
    @ScopeExtensions(TlsParameterType.GREASE_EXTENSION)
    @DynamicValueConstraints(
            affectedIdentifiers = "NAMED_GROUP",
            methods = "isNotKeyShareInInitialHello")
    @ComplianceCategory(SeverityLevel.MEDIUM)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    public void helloRetryGreaseExtension(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = getSharedTestWorkflowTrace(argumentAccessor, runner);
        ServerInitiatedExtensionPoints.sharedServerHelloGreaseExtensionTest(
                workflowTrace, runner, derivationContainer);
    }

    @AnvilTest(
            description =
                    "Clients MUST reject GREASE values when negotiated by the server. "
                            + "In particular, the client MUST fail the connection "
                            + "if a GREASE value appears in any of the following: "
                            + "[...] The \"version\" value in a ServerHello or HelloRetryRequest")
    @RFC(number = 8701, section = "4. Server-Initiated Extension Points")
    @ModelFromScope(modelType = "CERTIFICATE")
    @ScopeExtensions(TlsParameterType.GREASE_PROTOCOL_VERSION)
    @DynamicValueConstraints(
            affectedIdentifiers = "NAMED_GROUP",
            methods = "isNotKeyShareInInitialHello")
    @ComplianceCategory(SeverityLevel.MEDIUM)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    public void helloRetryGreaseVersionSelected(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = getSharedTestWorkflowTrace(argumentAccessor, runner);
        ServerInitiatedExtensionPoints.sharedGreaseVersionTest(
                workflowTrace, runner, derivationContainer);
    }

    private WorkflowTrace getSharedTestWorkflowTrace(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        runner.setAutoHelloRetryRequest(false);
        NamedGroup selectedGroup =
                derivationContainer.getDerivation(NamedGroupDerivation.class).getSelectedValue();
        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));
        runner.insertHelloRetryRequest(workflowTrace, selectedGroup);

        return workflowTrace;
    }

    @RFC(
            number = 8446,
            section =
                    "4.1.2 Client Hello, 4.1.3.  Server Hello, 4.1.4. Hello Retry Request, 4.2.8 Key Share, and 5.1. Record Layer")
    @AnvilTest(
            description =
                    "The client will also send a "
                            + "ClientHello when the server has responded to its ClientHello with a "
                            + "HelloRetryRequest. In that case, the client MUST send the same "
                            + "ClientHello without modification, except as follows: [...]"
                            + "Upon receiving a message with type server_hello, implementations MUST "
                            + "first examine the Random value and, if it matches this value, process "
                            + "it as described in Section 4.1.4). [...]"
                            + "Otherwise, the client MUST process all extensions in the "
                            + "HelloRetryRequest and send a second updated ClientHello. [...]"
                            + "Otherwise, when sending the new ClientHello, the client MUST replace the original \"key_share\" extension with one containing only a "
                            + "new KeyShareEntry for the group indicated in the selected_group field "
                            + "of the triggering HelloRetryRequest. [...]"
                            + "legacy_record_version:  MUST be set to 0x0303 for all records "
                            + "generated by a TLS 1.3 implementation other than an initial "
                            + "ClientHello [...]"
                            + "In order to maximize backward "
                            + "compatibility, a record containing an initial ClientHello SHOULD have "
                            + "version 0x0301 (reflecting TLS 1.0) and a record containing a second "
                            + "ClientHello or a ServerHello MUST have version 0x0303 (reflecting "
                            + "TLS 1.2).")
    @DynamicValueConstraints(
            affectedIdentifiers = "NAMED_GROUP",
            methods = "isNotKeyShareInInitialHello")
    @InteroperabilityCategory(SeverityLevel.HIGH)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    @Tag("adjusted")
    public void actsCorrectlyUponHelloRetryRequest(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace trace =
                runner.generateWorkflowTraceUntilLastSendingMessage(
                        WorkflowTraceType.SHORT_HELLO, HandshakeMessageType.SERVER_HELLO);

        runner.execute(trace, c)
                .validateFinal(
                        i -> {
                            WorkflowTrace executedTrace = i.getWorkflowTrace();
                            Validator.executedAsPlanned(i);

                            ClientHelloMessage firstClientHello =
                                    (ClientHelloMessage)
                                            WorkflowTraceUtil.getFirstReceivedMessage(
                                                    HandshakeMessageType.CLIENT_HELLO, trace);
                            ClientHelloMessage retryClientHello =
                                    (ClientHelloMessage)
                                            WorkflowTraceUtil.getLastReceivedMessage(
                                                    HandshakeMessageType.CLIENT_HELLO, trace);
                            assertTrue(
                                    "Did not receive two Client Hello messages",
                                    firstClientHello != null
                                            && retryClientHello != null
                                            && firstClientHello != retryClientHello);
                            testIfKeyShareWasUpdated(retryClientHello);
                            testIfRecordVersionWasAdjusted(executedTrace);
                            testIfExtensionsAreEqual(firstClientHello, retryClientHello);
                            testIfClientHelloFieldsAreEqual(firstClientHello, retryClientHello);
                        });
    }

    private void testIfRecordVersionWasAdjusted(WorkflowTrace executedTrace) {
        ReceiveAction receiveSecondHello = (ReceiveAction) executedTrace.getLastReceivingAction();
        for (Record record : receiveSecondHello.getReceivedRecords()) {
            if (record.getContentMessageType() == ProtocolMessageType.HANDSHAKE) {
                assertArrayEquals(
                        "Record Version was not adjusted after Hello Retry Request",
                        ((Record) record).getProtocolVersion().getValue(),
                        ProtocolVersion.TLS12.getValue());
            }
        }
    }

    private void testIfKeyShareWasUpdated(ClientHelloMessage retryClientHello) {
        KeyShareExtensionMessage keyShareExtension =
                retryClientHello.getExtension(KeyShareExtensionMessage.class);
        assertNotNull("No Key Share Extension provided in second ClientHello", keyShareExtension);
        List<KeyShareEntry> keyShareEntries = keyShareExtension.getKeyShareList();
        assertEquals(
                "Updated ClientHello did not contain exactly one key share",
                keyShareEntries.size(),
                1);
        assertEquals(
                "Updated ClientHello offered a different group then demanded by server",
                keyShareEntries.get(0).getGroupConfig(),
                derivationContainer.getDerivation(NamedGroupDerivation.class).getSelectedValue());
    }

    private void testIfExtensionsAreEqual(
            ClientHelloMessage firstClientHello, ClientHelloMessage retryClientHello) {
        // the client MUST send the same ClientHello without modification, except as follows:
        // -If a "key_share" extension was supplied in the HelloRetryRequest, replacing the list of
        // shares with a list containing a single
        //  KeyShareEntry from the indicated group.
        // (-Including a "cookie" extension if one was provided in the HelloRetryRequest)
        // -Updating the "pre_shared_key" extension if present by recomputing the
        // "obfuscated_ticket_age" and binder values
        //  and (optionally) removing any PSKs which are incompatible with the server’s indicated
        // cipher suite.
        // -Optionally adding, removing, or changing the length of the "padding" extension
        List<ExtensionType> extensionsInSecondHello = new LinkedList<>();
        retryClientHello
                .getExtensions()
                .forEach(
                        extension ->
                                extensionsInSecondHello.add(extension.getExtensionTypeConstant()));
        for (ExtensionMessage extension : firstClientHello.getExtensions()) {

            assertTrue(
                    "Extensions List not equal - second Client Hello did not contain "
                            + extension.getExtensionTypeConstant(),
                    retryClientHello.containsExtension(extension.getExtensionTypeConstant())
                            || extension.getExtensionTypeConstant() == ExtensionType.PADDING
                            || extension.getExtensionTypeConstant() == ExtensionType.EARLY_DATA
                            || extension.getExtensionTypeConstant() == ExtensionType.COOKIE
                            || extension.getExtensionTypeConstant()
                                    == ExtensionType.PRE_SHARED_KEY);

            if (extension.getExtensionTypeConstant() != ExtensionType.KEY_SHARE
                    && extension.getExtensionTypeConstant() != ExtensionType.PADDING
                    && extension.getExtensionTypeConstant() != ExtensionType.PRE_SHARED_KEY
                    && extension.getExtensionTypeConstant() != ExtensionType.EARLY_DATA
                    && extension.getExtensionTypeConstant() != ExtensionType.COOKIE) {
                assertTrue(
                        "Extension "
                                + extension.getExtensionTypeConstant()
                                + " is not identical to second Client Hello",
                        Arrays.equals(
                                extension.getExtensionBytes().getValue(),
                                retryClientHello
                                        .getExtension(extension.getClass())
                                        .getExtensionBytes()
                                        .getValue()));
            }
            extensionsInSecondHello.remove(extension.getExtensionTypeConstant());
        }

        // only these extensions may be added to retry Hello
        // we are not requesting a cookie value, that's a different test
        if (extensionsInSecondHello.size() > 0) {
            extensionsInSecondHello.remove(ExtensionType.PADDING);
            extensionsInSecondHello.remove(ExtensionType.KEY_SHARE);
        }
        assertTrue(
                "Second Client Hello contained additional Extensions: "
                        + extensionsInSecondHello.stream()
                                .map(ExtensionType::toString)
                                .collect(Collectors.joining(",")),
                extensionsInSecondHello.isEmpty());
    }

    private void testIfClientHelloFieldsAreEqual(
            ClientHelloMessage firstClientHello, ClientHelloMessage retryClientHello) {
        assertTrue(
                "Offered CipherSuites are not identical",
                Arrays.equals(
                        firstClientHello.getCipherSuites().getValue(),
                        retryClientHello.getCipherSuites().getValue()));
        assertTrue(
                "Offered CompressionList lengths are not identical",
                firstClientHello
                        .getCompressionLength()
                        .getValue()
                        .equals(retryClientHello.getCompressionLength().getValue()));
        assertTrue(
                "Selected ClientRandoms are not identical",
                Arrays.equals(
                        firstClientHello.getRandom().getValue(),
                        retryClientHello.getRandom().getValue()));
        assertTrue(
                "Selected ProtocolVersions are not identical",
                Arrays.equals(
                        firstClientHello.getProtocolVersion().getValue(),
                        retryClientHello.getProtocolVersion().getValue()));
        assertTrue(
                "TLS 1.3 compatibility SessionIDs are not identical",
                Arrays.equals(
                        firstClientHello.getSessionId().getValue(),
                        retryClientHello.getSessionId().getValue()));
    }

    public List<DerivationParameter> getTls12CipherSuites(DerivationScope scope) {
        List<DerivationParameter> parameterValues = new LinkedList<>();
        context.getFeatureExtractionResult()
                .getCipherSuites()
                .forEach(
                        cipherSuite -> parameterValues.add(new CipherSuiteDerivation(cipherSuite)));
        return parameterValues;
    }

    @AnvilTest(
            description =
                    "Similarly, cipher suites for TLS 1.2 and lower cannot be used with "
                            + "TLS 1.3.")
    @RFC(number = 8446, section = "B.4.  Cipher Suites")
    @DynamicValueConstraints(
            affectedIdentifiers = "NAMED_GROUP",
            methods = "isNotKeyShareInInitialHello")
    @ExplicitValues(affectedIdentifiers = "CIPHER_SUITE", methods = "getTls12CipherSuites")
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.MEDIUM)
    @SecurityCategory(SeverityLevel.LOW)
    public void helloRetryRequestsTls12CipherSuite(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        performHelloRetryRequestTest(argumentAccessor, runner);
    }

    @AnvilTest(
            description =
                    "When sending the new ClientHello, the client MUST copy "
                            + "the contents of the extension received in the HelloRetryRequest into "
                            + "a \"cookie\" extension in the new ClientHello.")
    @RFC(number = 8446, section = "4.2.2.  Cookie")
    @ScopeExtensions(TlsParameterType.HELLO_RETRY_COOKIE)
    @DynamicValueConstraints(
            affectedIdentifiers = "NAMED_GROUP",
            methods = "isNotKeyShareInInitialHello")
    @HandshakeCategory(SeverityLevel.HIGH)
    @ComplianceCategory(SeverityLevel.HIGH)
    @Tag("new")
    public void copiesCookieValue(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        config.setAddCookieExtension(true);
        runner.setAutoHelloRetryRequest(false);
        NamedGroup selectedGroup =
                derivationContainer.getDerivation(NamedGroupDerivation.class).getSelectedValue();

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsAction(new ReceiveAction(new ClientHelloMessage()));
        runner.insertHelloRetryRequest(workflowTrace, selectedGroup);

        runner.execute(workflowTrace, config)
                .validateFinal(
                        i -> {
                            Validator.executedAsPlanned(i);
                            ClientHelloMessage secondClientHello =
                                    (ClientHelloMessage)
                                            WorkflowTraceUtil.getLastReceivedMessage(
                                                    HandshakeMessageType.CLIENT_HELLO,
                                                    workflowTrace);
                            assertFalse(
                                    "Did not receive two ClientHello messages",
                                    secondClientHello
                                            == WorkflowTraceUtil.getFirstReceivedMessage(
                                                    HandshakeMessageType.CLIENT_HELLO,
                                                    workflowTrace));
                            assertTrue(
                                    "Did not receive a Cookie Extension in updated ClientHello",
                                    secondClientHello.containsExtension(ExtensionType.COOKIE));
                            byte[] receivedCookie =
                                    secondClientHello
                                            .getExtension(CookieExtensionMessage.class)
                                            .getCookie()
                                            .getValue();
                            assertArrayEquals(
                                    "Client sent a wrong cookie value",
                                    receivedCookie,
                                    config.getDefaultExtensionCookie());
                        });
    }
}
