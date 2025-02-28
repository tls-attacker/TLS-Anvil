/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlstest.suite.tests.server.tls13.rfc8446;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.IncludeParameter;
import de.rub.nds.anvilcore.annotation.MethodCondition;
import de.rub.nds.anvilcore.annotation.ServerTest;
import de.rub.nds.anvilcore.teststate.AnvilTestCase;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PSKKeyExchangeModesExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PreSharedKeyExtensionMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceConfigurationUtil;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceResultUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.derivationParameter.CipherSuiteDerivation;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;

@ServerTest
public class PreSharedKey extends Tls13Test {

    public static final String PSK_HANDSHAKES_NOT_SUPPORTED = "SUT does not support PSK handshakes";

    public ConditionEvaluationResult supportsPsk() {
        if (context.getFeatureExtractionResult().getResult(TlsAnalyzedProperty.SUPPORTS_TLS13_PSK)
                        == TestResults.TRUE
                || context.getFeatureExtractionResult()
                                .getResult(TlsAnalyzedProperty.SUPPORTS_TLS13_PSK_DHE)
                        == TestResults.TRUE) {
            return ConditionEvaluationResult.enabled("");
        } else {
            return ConditionEvaluationResult.disabled(PSK_HANDSHAKES_NOT_SUPPORTED);
        }
    }

    @SuppressWarnings("unused")
    public ConditionEvaluationResult supportsMultipleHdkfHashesAndPsk() {
        Set<HKDFAlgorithm> hkdfAlgorithms = new HashSet<>();
        Set<CipherSuite> tls13CipherSuites =
                context.getFeatureExtractionResult().getSupportedTls13CipherSuites();
        if (tls13CipherSuites != null && !tls13CipherSuites.isEmpty()) {
            tls13CipherSuites.forEach(
                    cipher -> {
                        if (!cipher.isGrease()) {
                            hkdfAlgorithms.add(AlgorithmResolver.getHKDFAlgorithm(cipher));
                        }
                    });
        }
        if (hkdfAlgorithms.size() < 2) {
            return ConditionEvaluationResult.disabled("Does not support multiple HKDF Hashes");
        }
        return supportsPsk();
    }

    @SuppressWarnings("unused")
    public ConditionEvaluationResult supportsPskOnlyHandshake() {
        if (context.getFeatureExtractionResult().getResult(TlsAnalyzedProperty.SUPPORTS_TLS13_PSK)
                == TestResults.TRUE) {
            return ConditionEvaluationResult.enabled("");
        } else {
            return ConditionEvaluationResult.disabled(PSK_HANDSHAKES_NOT_SUPPORTED);
        }
    }

    @SuppressWarnings("unused")
    public ConditionEvaluationResult supportsPskDheHandshake() {
        if (context.getFeatureExtractionResult()
                        .getResult(TlsAnalyzedProperty.SUPPORTS_TLS13_PSK_DHE)
                == TestResults.TRUE) {
            return ConditionEvaluationResult.enabled("");
        } else {
            return ConditionEvaluationResult.disabled(PSK_HANDSHAKES_NOT_SUPPORTED);
        }
    }

    @AnvilTest(id = "8446-8RhYHEGBvv")
    @MethodCondition(method = "supportsPsk")
    @Tag("new")
    public void isNotLastExtension(AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);
        config.setAddPSKKeyExchangeModesExtension(true);
        adjustPreSharedKeyModes(config);
        WorkflowTrace workflowTrace = getExtensionPositionModifiedTrace(runner, config);

        State state = runner.execute(workflowTrace, config);

        Validator.receivedFatalAlert(state, testCase);
        Validator.testAlertDescription(state, testCase, AlertDescription.ILLEGAL_PARAMETER);
    }

    private WorkflowTrace getExtensionPositionModifiedTrace(WorkflowRunner runner, Config config) {
        WorkflowTrace workflowTrace =
                runner.generateWorkflowTraceUntilLastReceivingMessage(
                        WorkflowTraceType.FULL_TLS13_PSK, HandshakeMessageType.SERVER_HELLO);
        ClientHelloMessage resumingHello =
                (ClientHelloMessage)
                        WorkflowTraceConfigurationUtil.getLastStaticConfiguredSendMessage(
                                workflowTrace, HandshakeMessageType.CLIENT_HELLO);
        resumingHello
                .getExtensions()
                .add(
                        resumingHello.getExtensions().size() - 2,
                        new PreSharedKeyExtensionMessage(config));
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));
        return workflowTrace;
    }

    @AnvilTest(id = "8446-K5PYwUqs8E")
    @MethodCondition(method = "supportsPsk")
    @Tag("new")
    public void isLastButDuplicatedExtension(AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);
        setupPskConfig(config);
        WorkflowTrace workflowTrace = getExtensionPositionModifiedTrace(runner, config);

        State state = runner.execute(workflowTrace, config);

        Validator.receivedFatalAlert(state, testCase);
        Validator.testAlertDescription(state, testCase, AlertDescription.ILLEGAL_PARAMETER);
    }

    @AnvilTest(id = "8446-Hq5yKcFcmQ")
    @MethodCondition(method = "supportsPskOnlyHandshake")
    @Tag("new")
    public void respectsKeyExchangeChoicePskOnly(AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);
        config.setAddPSKKeyExchangeModesExtension(true);
        config.setAddPreSharedKeyExtension(true);
        List<PskKeyExchangeMode> pskModes = new LinkedList<>();
        pskModes.add(PskKeyExchangeMode.PSK_KE);
        config.setAddKeyShareExtension(false);
        config.setPSKKeyExchangeModes(pskModes);

        WorkflowTrace workflowTrace =
                runner.generateWorkflowTrace(WorkflowTraceType.FULL_TLS13_PSK);

        State state = runner.execute(workflowTrace, config);

        Validator.executedAsPlanned(state, testCase);
        ServerHelloMessage secondServerHello =
                (ServerHelloMessage)
                        WorkflowTraceResultUtil.getLastReceivedMessage(
                                workflowTrace, HandshakeMessageType.SERVER_HELLO);
        if (secondServerHello.containsExtension(ExtensionType.PRE_SHARED_KEY)) {
            assertFalse(
                    secondServerHello.containsExtension(ExtensionType.KEY_SHARE),
                    "Server ignored Key Exchange Mode and sent a Key Share Extension");
        }
    }

    @AnvilTest(id = "8446-Eqo9cmGAET")
    @MethodCondition(method = "supportsPskDheHandshake")
    @Tag("new")
    public void respectsKeyExchangeChoicePskDhe(AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);
        config.setAddPSKKeyExchangeModesExtension(true);
        config.setAddPreSharedKeyExtension(true);
        List<PskKeyExchangeMode> pskModes = new LinkedList<>();
        pskModes.add(PskKeyExchangeMode.PSK_DHE_KE);
        config.setPSKKeyExchangeModes(pskModes);

        WorkflowTrace workflowTrace =
                runner.generateWorkflowTrace(WorkflowTraceType.FULL_TLS13_PSK);

        State state = runner.execute(workflowTrace, config);

        Validator.executedAsPlanned(state, testCase);
        ServerHelloMessage secondServerHello =
                (ServerHelloMessage)
                        WorkflowTraceResultUtil.getLastReceivedMessage(
                                workflowTrace, HandshakeMessageType.SERVER_HELLO);
        if (secondServerHello.containsExtension(ExtensionType.PRE_SHARED_KEY)) {
            assertTrue(
                    secondServerHello.containsExtension(ExtensionType.KEY_SHARE),
                    "Server ignored Key Exchange Mode and did not send a Key Share Extension");
        }
    }

    @AnvilTest(id = "8446-AGtoN1G2B3")
    @IncludeParameter("PRF_BITMASK")
    @MethodCondition(method = "supportsPsk")
    public void invalidBinder(AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);
        setupPskConfig(config);
        config.setLimitPsksToOne(true);
        WorkflowTrace workflowTrace =
                runner.generateWorkflowTraceUntilLastReceivingMessage(
                        WorkflowTraceType.FULL_TLS13_PSK, HandshakeMessageType.SERVER_HELLO);
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));
        byte[] modificationBitmask = parameterCombination.buildBitmask();

        ClientHelloMessage cHello =
                (ClientHelloMessage)
                        WorkflowTraceConfigurationUtil.getLastStaticConfiguredSendMessage(
                                workflowTrace, HandshakeMessageType.CLIENT_HELLO);
        PreSharedKeyExtensionMessage pskExt =
                cHello.getExtension(PreSharedKeyExtensionMessage.class);
        pskExt.setBinderListBytes(
                Modifiable.xor(modificationBitmask, ExtensionByteLength.PSK_BINDER_LENGTH));

        State state = runner.execute(workflowTrace, config);

        Validator.receivedFatalAlert(state, testCase, false);
    }

    @AnvilTest(id = "8446-1SEHo5n8WM")
    @MethodCondition(method = "supportsPsk")
    public void noBinder(AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);
        setupPskConfig(config);
        config.setLimitPsksToOne(true);

        WorkflowTrace workflowTrace =
                runner.generateWorkflowTraceUntilLastReceivingMessage(
                        WorkflowTraceType.FULL_TLS13_PSK, HandshakeMessageType.SERVER_HELLO);
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));

        ClientHelloMessage cHello =
                (ClientHelloMessage)
                        WorkflowTraceConfigurationUtil.getLastStaticConfiguredSendMessage(
                                workflowTrace, HandshakeMessageType.CLIENT_HELLO);
        PreSharedKeyExtensionMessage pskExt =
                cHello.getExtension(PreSharedKeyExtensionMessage.class);
        pskExt.setBinderListBytes(Modifiable.explicit(new byte[0]));
        pskExt.setBinderListLength(Modifiable.explicit(0));

        State state = runner.execute(workflowTrace, config);

        Validator.receivedFatalAlert(state, testCase, false);
    }

    @AnvilTest(id = "8446-2eQTsmq7d1")
    @MethodCondition(method = "supportsPsk")
    public void selectedPSKIndexIsWithinOfferedListSize(
            AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);
        setupPskConfig(config);

        WorkflowTrace workflowTrace;
        if (config.getTls13BackwardsCompatibilityMode()) {
            workflowTrace =
                    runner.generateWorkflowTraceUntilLastSendingMessage(
                            WorkflowTraceType.FULL_TLS13_PSK,
                            ProtocolMessageType.CHANGE_CIPHER_SPEC);
        } else {
            workflowTrace =
                    runner.generateWorkflowTraceUntilLastSendingMessage(
                            WorkflowTraceType.FULL_TLS13_PSK, HandshakeMessageType.FINISHED);
        }

        State state = runner.execute(workflowTrace, config);

        WorkflowTrace trace = state.getWorkflowTrace();
        Validator.executedAsPlanned(state, testCase);

        ClientHelloMessage pskClientHello =
                (ClientHelloMessage)
                        WorkflowTraceResultUtil.getLastSentMessage(
                                trace, HandshakeMessageType.CLIENT_HELLO);
        PreSharedKeyExtensionMessage pskExtension =
                pskClientHello.getExtension(PreSharedKeyExtensionMessage.class);
        int offeredPSKs = pskExtension.getIdentities().size();

        ServerHelloMessage pskServerHello =
                (ServerHelloMessage)
                        WorkflowTraceResultUtil.getLastReceivedMessage(
                                trace, HandshakeMessageType.SERVER_HELLO);
        assertTrue(
                pskServerHello.containsExtension(ExtensionType.PRE_SHARED_KEY),
                "PSK Handshake failed - Server did not select as PSK");
        int selectedIdentityIndex =
                pskServerHello
                        .getExtension(PreSharedKeyExtensionMessage.class)
                        .getSelectedIdentity()
                        .getValue();
        assertTrue(
                selectedIdentityIndex >= 0 && selectedIdentityIndex < offeredPSKs,
                "Server set an invalid selected PSK index ("
                        + selectedIdentityIndex
                        + " of "
                        + offeredPSKs
                        + " )");
    }

    @AnvilTest(id = "8446-Yo68xBhELu")
    @MethodCondition(method = "supportsMultipleHdkfHashesAndPsk")
    @Tag("new")
    public void resumeWithCipherWithDifferentHkdfHash(
            AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);
        setupPskConfig(config);
        WorkflowTrace workflowTrace =
                runner.generateWorkflowTraceUntilLastSendingMessage(
                        WorkflowTraceType.FULL_TLS13_PSK, HandshakeMessageType.FINISHED);
        ClientHelloMessage modifiedClientHello =
                (ClientHelloMessage)
                        WorkflowTraceConfigurationUtil.getLastStaticConfiguredSendMessage(
                                workflowTrace, HandshakeMessageType.CLIENT_HELLO);

        CipherSuite selectedCipher =
                parameterCombination.getParameter(CipherSuiteDerivation.class).getSelectedValue();
        CipherSuite otherHkdfHashCipher = null;
        for (CipherSuite cipher :
                context.getFeatureExtractionResult().getSupportedTls13CipherSuites()) {
            if (AlgorithmResolver.getHKDFAlgorithm(cipher)
                    != AlgorithmResolver.getHKDFAlgorithm(selectedCipher)) {
                otherHkdfHashCipher = cipher;
                break;
            }
        }
        assertNotNull(otherHkdfHashCipher);
        modifiedClientHello.setCipherSuites(
                Modifiable.explicit(otherHkdfHashCipher.getByteValue()));

        State state = runner.execute(workflowTrace, config);

        ServerHelloMessage lastHello =
                state.getWorkflowTrace().getLastReceivedMessage(ServerHelloMessage.class);
        assertNotNull(lastHello, "Received no ServerHello");
        // the server might abort before sending the 2nd server hello but this
        // check should always succeed
        assertFalse(
                lastHello.containsExtension(ExtensionType.PRE_SHARED_KEY),
                "Server accepted the PSK of a different HKDF Hash");
    }

    @AnvilTest(id = "8446-mwDQtBNg4o")
    public void sendPskExtensionWithoutPskKeyExchangeModes(
            AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);
        setupPskConfig(config);

        WorkflowTrace workflowTrace =
                runner.generateWorkflowTraceUntilLastSendingMessage(
                        WorkflowTraceType.FULL_TLS13_PSK, HandshakeMessageType.CLIENT_HELLO);
        ClientHelloMessage resumingHello = new ClientHelloMessage(config);
        resumingHello
                .getExtensions()
                .remove(resumingHello.getExtension(PSKKeyExchangeModesExtensionMessage.class));
        workflowTrace.addTlsAction(new SendAction(resumingHello));
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));

        State state = runner.execute(workflowTrace, config);

        if (WorkflowTraceResultUtil.didReceiveMessage(
                state.getWorkflowTrace(), HandshakeMessageType.NEW_SESSION_TICKET)) {
            Validator.receivedFatalAlert(state, testCase);
        }
    }

    private void setupPskConfig(Config config) {
        config.setAddPSKKeyExchangeModesExtension(true);
        config.setAddPreSharedKeyExtension(true);
        adjustPreSharedKeyModes(config);
    }
}
