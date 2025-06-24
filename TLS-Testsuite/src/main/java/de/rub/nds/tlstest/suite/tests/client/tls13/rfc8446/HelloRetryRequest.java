/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.client.tls13.rfc8446;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.anvilcore.annotation.*;
import de.rub.nds.anvilcore.coffee4j.model.ModelFromScope;
import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.teststate.AnvilTestCase;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.CookieExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SupportedVersionsExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareEntry;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceConfigurationUtil;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceResultUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.ClientFeatureExtractionResult;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
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

@ClientTest
public class HelloRetryRequest extends Tls13Test {

    public List<DerivationParameter<Config, NamedGroup>> getUnofferedGroups(DerivationScope scope) {
        List<DerivationParameter<Config, NamedGroup>> parameterValues = new LinkedList<>();
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

    @AnvilTest(id = "8446-2L9AK4xSva")
    @ExplicitValues(affectedIdentifiers = "NAMED_GROUP", methods = "getUnofferedGroups")
    public void helloRetryRequestsUnofferedGroup(AnvilTestCase testCase, WorkflowRunner runner) {
        performHelloRetryRequestTest(testCase, runner);
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

    @AnvilTest(id = "8446-bfziReZMw4")
    @ExplicitValues(affectedIdentifiers = "CIPHER_SUITE", methods = "getUnofferedTls13CipherSuites")
    public void helloRetryRequestsUnofferedTls13CipherSuite(
            AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);
        runner.setAutoHelloRetryRequest(false);
        NamedGroup selectedGroup =
                parameterCombination.getParameter(NamedGroupDerivation.class).getSelectedValue();

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(new ReceiveAction(new AlertMessage()));
        runner.insertHelloRetryRequest(workflowTrace, selectedGroup);

        State state = runner.execute(workflowTrace, c);

        Validator.receivedFatalAlert(state, testCase);
        AlertMessage alert = state.getWorkflowTrace().getFirstReceivedMessage(AlertMessage.class);
        // illegal parameter is not mentioned in the quote above but is
        // mandatory
        // for the ServerHello case
        Validator.testAlertDescription(state, testCase, AlertDescription.ILLEGAL_PARAMETER, alert);
    }

    public boolean isKeyShareInInitialHello(NamedGroup group) {
        return ((ClientFeatureExtractionResult) context.getFeatureExtractionResult())
                .getClientHelloKeyShareGroups()
                .contains(group);
    }

    @AnvilTest(id = "8446-s2k4bG3Gz9")
    @DynamicValueConstraints(
            affectedIdentifiers = "NAMED_GROUP",
            methods = "isKeyShareInInitialHello")
    public void helloRetryRequestResultsInNoChanges(AnvilTestCase testCase, WorkflowRunner runner) {
        performHelloRetryRequestTest(testCase, runner);
    }

    private void performHelloRetryRequestTest(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);
        runner.setAutoHelloRetryRequest(false);
        NamedGroup selectedGroup =
                parameterCombination.getParameter(NamedGroupDerivation.class).getSelectedValue();

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(new ReceiveAction(new AlertMessage()));
        runner.insertHelloRetryRequest(workflowTrace, selectedGroup);

        State state = runner.execute(workflowTrace, c);

        Validator.receivedFatalAlert(state, testCase);
        AlertMessage alert = state.getWorkflowTrace().getFirstReceivedMessage(AlertMessage.class);
        Validator.testAlertDescription(state, testCase, AlertDescription.ILLEGAL_PARAMETER, alert);
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

    @AnvilTest(id = "8446-FviCUju7gw")
    @DynamicValueConstraints(
            affectedIdentifiers = "NAMED_GROUP",
            methods = "isNotKeyShareInInitialHello")
    @MethodCondition(method = "supportsMultipleNamedGroups")
    public void sendSecondHelloRetryRequest(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);
        WorkflowTrace workflowTrace = new WorkflowTrace();
        NamedGroup selectedGroup =
                parameterCombination.getParameter(NamedGroupDerivation.class).getSelectedValue();
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

        State state = runner.execute(workflowTrace, c);

        assertFalse(
                WorkflowTraceResultUtil.getLastReceivedMessage(state.getWorkflowTrace())
                                instanceof ClientHelloMessage
                        && state.getWorkflowTrace().getLastReceivingAction().getReceivedMessages()
                                != null
                        && state.getWorkflowTrace()
                                .getLastReceivingAction()
                                .getReceivedMessages()
                                .contains(
                                        WorkflowTraceResultUtil.getLastReceivedMessage(
                                                state.getWorkflowTrace())),
                "Client replied to second HelloRetryRequest with ClientHello");
        Validator.receivedFatalAlert(state, testCase);
        AlertMessage alert = state.getWorkflowTrace().getFirstReceivedMessage(AlertMessage.class);
        Validator.testAlertDescription(state, testCase, AlertDescription.UNEXPECTED_MESSAGE, alert);
    }

    private ConditionEvaluationResult supportsMultipleCipherSuites() {
        if (context.getFeatureExtractionResult().getSupportedTls13CipherSuites().size() > 1) {
            return ConditionEvaluationResult.enabled(
                    "More than one CipherSuite supported by target in TLS 1.3");
        }
        return ConditionEvaluationResult.disabled(
                "Target does not support more than one CipherSuite in TLS 1.3");
    }

    @AnvilTest(id = "8446-f3pZavKkyP")
    @IncludeParameter("MIRRORED_CIPHERSUITE")
    @DynamicValueConstraints(
            affectedIdentifiers = "NAMED_GROUP",
            methods = "isNotKeyShareInInitialHello")
    @MethodCondition(method = "supportsMultipleCipherSuites")
    public void cipherSuiteDisparity(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);
        runner.setAutoHelloRetryRequest(false);
        NamedGroup selectedGroup =
                parameterCombination.getParameter(NamedGroupDerivation.class).getSelectedValue();
        CipherSuite helloRetryCipherSuite =
                parameterCombination
                        .getParameter(MirroredCipherSuiteDerivation.class)
                        .getSelectedValue();

        WorkflowTrace workflowTrace =
                runner.generateWorkflowTraceUntilReceivingMessage(
                        WorkflowTraceType.HANDSHAKE, ProtocolMessageType.CHANGE_CIPHER_SPEC);

        workflowTrace.addTlsActions(new ReceiveAction(new AlertMessage()));
        runner.insertHelloRetryRequest(workflowTrace, selectedGroup);
        ServerHelloMessage helloRetryRequest =
                (ServerHelloMessage)
                        WorkflowTraceConfigurationUtil.getFirstStaticConfiguredSendMessage(
                                workflowTrace, HandshakeMessageType.SERVER_HELLO);
        helloRetryRequest.setSelectedCipherSuite(
                Modifiable.explicit(helloRetryCipherSuite.getByteValue()));

        State state = runner.execute(workflowTrace, c);

        Validator.receivedFatalAlert(state, testCase);
        AlertMessage alert = state.getWorkflowTrace().getFirstReceivedMessage(AlertMessage.class);
        Validator.testAlertDescription(state, testCase, AlertDescription.ILLEGAL_PARAMETER, alert);
    }

    @AnvilTest(id = "8446-KLkH56oYzC")
    @IncludeParameter("MIRRORED_CIPHERSUITE")
    @DynamicValueConstraints(
            affectedIdentifiers = "NAMED_GROUP",
            methods = "isNotKeyShareInInitialHello")
    @ManualConfig(identifiers = "NAMED_GROUP")
    @Tag("new")
    public void namedGroupDisparity(AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);
        runner.setAutoHelloRetryRequest(false);
        NamedGroup actualHelloGroup =
                ((ClientFeatureExtractionResult) context.getFeatureExtractionResult())
                        .getClientHelloNamedGroups().stream()
                                .filter(ng -> NamedGroup.getImplemented().contains(ng))
                                .findFirst()
                                .get();
        config.setDefaultServerNamedGroups(actualHelloGroup);
        config.setDefaultSelectedNamedGroup(actualHelloGroup);

        NamedGroup hrrNamedGroup =
                parameterCombination.getParameter(NamedGroupDerivation.class).getSelectedValue();
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.SHORT_HELLO);
        runner.insertHelloRetryRequest(workflowTrace, hrrNamedGroup);
        workflowTrace.addTlsActions(new ReceiveAction(new AlertMessage()));

        State state = runner.execute(workflowTrace, config);

        Validator.receivedFatalAlert(state, testCase);
        AlertMessage alert = state.getWorkflowTrace().getFirstReceivedMessage(AlertMessage.class);
        Validator.testAlertDescription(state, testCase, AlertDescription.ILLEGAL_PARAMETER, alert);
    }

    @AnvilTest(id = "8446-ncR52WSgGx")
    @IncludeParameter("MIRRORED_CIPHERSUITE")
    @DynamicValueConstraints(
            affectedIdentifiers = "NAMED_GROUP",
            methods = "isNotKeyShareInInitialHello")
    @Tag("new")
    public void versionDisparity(AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);
        runner.setAutoHelloRetryRequest(false);
        NamedGroup selectedGroup =
                parameterCombination.getParameter(NamedGroupDerivation.class).getSelectedValue();

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

        State state = runner.execute(workflowTrace, config);

        Validator.receivedFatalAlert(state, testCase);
        AlertMessage alert = state.getWorkflowTrace().getFirstReceivedMessage(AlertMessage.class);
        Validator.testAlertDescription(state, testCase, AlertDescription.ILLEGAL_PARAMETER, alert);
    }

    @AnvilTest(id = "8446-6X9hLRk9V4")
    @DynamicValueConstraints(
            affectedIdentifiers = "NAMED_GROUP",
            methods = "isNotKeyShareInInitialHello")
    public void helloRetryLegacySessionId(AnvilTestCase testCase, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = getSharedTestWorkflowTrace(runner);
        ServerHello.sharedSessionIdTest(workflowTrace, runner, testCase);
    }

    @AnvilTest(id = "8446-dyTnCEsFo1")
    @DynamicValueConstraints(
            affectedIdentifiers = "NAMED_GROUP",
            methods = "isNotKeyShareInInitialHello")
    public void helloRetryCompressionValue(AnvilTestCase testCase, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = getSharedTestWorkflowTrace(runner);
        ServerHello.sharedCompressionValueTest(workflowTrace, runner, testCase);
    }

    @AnvilTest(id = "8446-qN6nNMX9Sx")
    @IncludeParameter("GREASE_CIPHERSUITE")
    @ExcludeParameter("CIPHER_SUITE")
    @DynamicValueConstraints(
            affectedIdentifiers = "NAMED_GROUP",
            methods = "isNotKeyShareInInitialHello")
    public void helloRetryGreaseCipherSuite(AnvilTestCase testCase, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = getSharedTestWorkflowTrace(runner);
        ServerInitiatedExtensionPoints.sharedGreaseCipherSuiteTest(
                workflowTrace, runner, parameterCombination, testCase);
    }

    @AnvilTest(id = "8446-TyCkZKkVMt")
    @ModelFromScope(modelType = "CERTIFICATE")
    @IncludeParameter("GREASE_EXTENSION")
    @DynamicValueConstraints(
            affectedIdentifiers = "NAMED_GROUP",
            methods = "isNotKeyShareInInitialHello")
    public void helloRetryGreaseExtension(AnvilTestCase testCase, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = getSharedTestWorkflowTrace(runner);
        ServerInitiatedExtensionPoints.sharedServerHelloGreaseExtensionTest(
                workflowTrace, runner, parameterCombination, testCase);
    }

    @AnvilTest(id = "8446-vU6BQin9Eo")
    @ModelFromScope(modelType = "CERTIFICATE")
    @IncludeParameter("GREASE_PROTOCOL_VERSION")
    @DynamicValueConstraints(
            affectedIdentifiers = "NAMED_GROUP",
            methods = "isNotKeyShareInInitialHello")
    public void helloRetryGreaseVersionSelected(AnvilTestCase testCase, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = getSharedTestWorkflowTrace(runner);
        ServerInitiatedExtensionPoints.sharedGreaseVersionTest(
                workflowTrace, runner, parameterCombination, testCase);
    }

    private WorkflowTrace getSharedTestWorkflowTrace(WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);
        runner.setAutoHelloRetryRequest(false);
        NamedGroup selectedGroup =
                parameterCombination.getParameter(NamedGroupDerivation.class).getSelectedValue();
        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));
        runner.insertHelloRetryRequest(workflowTrace, selectedGroup);

        return workflowTrace;
    }

    @AnvilTest(id = "8446-5NRGuXE3Em")
    @DynamicValueConstraints(
            affectedIdentifiers = "NAMED_GROUP",
            methods = "isNotKeyShareInInitialHello")
    @Tag("adjusted")
    public void actsCorrectlyUponHelloRetryRequest(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);
        WorkflowTrace trace =
                runner.generateWorkflowTraceUntilLastSendingMessage(
                        WorkflowTraceType.SHORT_HELLO, HandshakeMessageType.SERVER_HELLO);

        State state = runner.execute(trace, c);

        WorkflowTrace executedTrace = state.getWorkflowTrace();
        Validator.executedAsPlanned(state, testCase);

        ClientHelloMessage firstClientHello =
                (ClientHelloMessage)
                        WorkflowTraceResultUtil.getFirstReceivedMessage(
                                trace, HandshakeMessageType.CLIENT_HELLO);
        ClientHelloMessage retryClientHello =
                (ClientHelloMessage)
                        WorkflowTraceResultUtil.getLastReceivedMessage(
                                trace, HandshakeMessageType.CLIENT_HELLO);
        assertTrue(
                firstClientHello != null
                        && retryClientHello != null
                        && firstClientHello != retryClientHello,
                "Did not receive two Client Hello messages");
        testIfKeyShareWasUpdated(retryClientHello);
        testIfRecordVersionWasAdjusted(executedTrace);
        testIfExtensionsAreEqual(firstClientHello, retryClientHello);
        testIfClientHelloFieldsAreEqual(firstClientHello, retryClientHello);
    }

    private void testIfRecordVersionWasAdjusted(WorkflowTrace executedTrace) {
        ReceiveAction receiveSecondHello = (ReceiveAction) executedTrace.getLastReceivingAction();
        for (Record record : receiveSecondHello.getReceivedRecords()) {
            if (record.getContentMessageType() == ProtocolMessageType.HANDSHAKE) {
                assertArrayEquals(
                        ((Record) record).getProtocolVersion().getValue(),
                        ProtocolVersion.TLS12.getValue(),
                        "Record Version was not adjusted after Hello Retry Request");
            }
        }
    }

    private void testIfKeyShareWasUpdated(ClientHelloMessage retryClientHello) {
        KeyShareExtensionMessage keyShareExtension =
                retryClientHello.getExtension(KeyShareExtensionMessage.class);
        assertNotNull(keyShareExtension, "No Key Share Extension provided in second ClientHello");
        List<KeyShareEntry> keyShareEntries = keyShareExtension.getKeyShareList();
        assertEquals(
                keyShareEntries.size(),
                1,
                "Updated ClientHello did not contain exactly one key share");
        assertEquals(
                keyShareEntries.get(0).getGroupConfig(),
                parameterCombination.getParameter(NamedGroupDerivation.class).getSelectedValue(),
                "Updated ClientHello offered a different group then demanded by server");
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
                    retryClientHello.containsExtension(extension.getExtensionTypeConstant())
                            || extension.getExtensionTypeConstant() == ExtensionType.PADDING
                            || extension.getExtensionTypeConstant() == ExtensionType.EARLY_DATA
                            || extension.getExtensionTypeConstant() == ExtensionType.COOKIE
                            || extension.getExtensionTypeConstant() == ExtensionType.PRE_SHARED_KEY,
                    "Extensions List not equal - second Client Hello did not contain "
                            + extension.getExtensionTypeConstant());

            if (extension.getExtensionTypeConstant() != ExtensionType.KEY_SHARE
                    && extension.getExtensionTypeConstant() != ExtensionType.PADDING
                    && extension.getExtensionTypeConstant() != ExtensionType.PRE_SHARED_KEY
                    && extension.getExtensionTypeConstant() != ExtensionType.EARLY_DATA
                    && extension.getExtensionTypeConstant() != ExtensionType.COOKIE) {
                assertTrue(
                        Arrays.equals(
                                extension.getExtensionBytes().getValue(),
                                retryClientHello
                                        .getExtension(extension.getClass())
                                        .getExtensionBytes()
                                        .getValue()),
                        "Extension "
                                + extension.getExtensionTypeConstant()
                                + " is not identical to second Client Hello");
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
                extensionsInSecondHello.isEmpty(),
                "Second Client Hello contained additional Extensions: "
                        + extensionsInSecondHello.stream()
                                .map(ExtensionType::toString)
                                .collect(Collectors.joining(",")));
    }

    private void testIfClientHelloFieldsAreEqual(
            ClientHelloMessage firstClientHello, ClientHelloMessage retryClientHello) {
        assertTrue(
                Arrays.equals(
                        firstClientHello.getCipherSuites().getValue(),
                        retryClientHello.getCipherSuites().getValue()),
                "Offered CipherSuites are not identical");
        assertTrue(
                firstClientHello
                        .getCompressionLength()
                        .getValue()
                        .equals(retryClientHello.getCompressionLength().getValue()),
                "Offered CompressionList lengths are not identical");
        assertTrue(
                Arrays.equals(
                        firstClientHello.getRandom().getValue(),
                        retryClientHello.getRandom().getValue()),
                "Selected ClientRandoms are not identical");
        assertTrue(
                Arrays.equals(
                        firstClientHello.getProtocolVersion().getValue(),
                        retryClientHello.getProtocolVersion().getValue()),
                "Selected ProtocolVersions are not identical");
        assertTrue(
                Arrays.equals(
                        firstClientHello.getSessionId().getValue(),
                        retryClientHello.getSessionId().getValue()),
                "TLS 1.3 compatibility SessionIDs are not identical");
    }

    public List<DerivationParameter> getTls12CipherSuites(DerivationScope scope) {
        List<DerivationParameter> parameterValues = new LinkedList<>();
        context.getFeatureExtractionResult()
                .getCipherSuites()
                .forEach(
                        cipherSuite -> parameterValues.add(new CipherSuiteDerivation(cipherSuite)));
        return parameterValues;
    }

    @AnvilTest(id = "8446-7byKPGEA8Q")
    @DynamicValueConstraints(
            affectedIdentifiers = "NAMED_GROUP",
            methods = "isNotKeyShareInInitialHello")
    @ExplicitValues(affectedIdentifiers = "CIPHER_SUITE", methods = "getTls12CipherSuites")
    public void helloRetryRequestsTls12CipherSuite(AnvilTestCase testCase, WorkflowRunner runner) {
        performHelloRetryRequestTest(testCase, runner);
    }

    @AnvilTest(id = "8446-2v6S87AwgY")
    @IncludeParameter("HELLO_RETRY_COOKIE")
    @DynamicValueConstraints(
            affectedIdentifiers = "NAMED_GROUP",
            methods = "isNotKeyShareInInitialHello")
    @Tag("new")
    public void copiesCookieValue(AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);
        config.setAddCookieExtension(true);
        runner.setAutoHelloRetryRequest(false);
        NamedGroup selectedGroup =
                parameterCombination.getParameter(NamedGroupDerivation.class).getSelectedValue();

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsAction(new ReceiveAction(new ClientHelloMessage()));
        runner.insertHelloRetryRequest(workflowTrace, selectedGroup);

        State state = runner.execute(workflowTrace, config);

        Validator.executedAsPlanned(state, testCase);
        ClientHelloMessage secondClientHello =
                (ClientHelloMessage)
                        WorkflowTraceResultUtil.getLastReceivedMessage(
                                workflowTrace, HandshakeMessageType.CLIENT_HELLO);
        assertFalse(
                secondClientHello
                        == WorkflowTraceResultUtil.getFirstReceivedMessage(
                                workflowTrace, HandshakeMessageType.CLIENT_HELLO),
                "Did not receive two ClientHello messages");
        assertTrue(
                secondClientHello.containsExtension(ExtensionType.COOKIE),
                "Did not receive a Cookie Extension in updated ClientHello");
        byte[] receivedCookie =
                secondClientHello.getExtension(CookieExtensionMessage.class).getCookie().getValue();
        assertArrayEquals(
                receivedCookie,
                config.getDefaultExtensionCookie(),
                "Client sent a wrong cookie value");
    }
}
