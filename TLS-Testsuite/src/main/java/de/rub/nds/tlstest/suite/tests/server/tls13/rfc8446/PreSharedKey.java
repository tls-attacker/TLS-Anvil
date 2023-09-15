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

import static org.junit.Assert.*;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.IncludeParameter;
import de.rub.nds.anvilcore.annotation.MethodCondition;
import de.rub.nds.anvilcore.annotation.ServerTest;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PSKKeyExchangeModesExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PreSharedKeyExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
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
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@ServerTest
public class PreSharedKey extends Tls13Test {

    public ConditionEvaluationResult supportsPsk() {
        if (context.getFeatureExtractionResult().getResult(TlsAnalyzedProperty.SUPPORTS_TLS13_PSK)
                        == TestResults.TRUE
                || context.getFeatureExtractionResult()
                                .getResult(TlsAnalyzedProperty.SUPPORTS_TLS13_PSK_DHE)
                        == TestResults.TRUE) {
            return ConditionEvaluationResult.enabled("");
        } else {
            return ConditionEvaluationResult.disabled("Does not support PSK handshakes");
        }
    }

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

    public ConditionEvaluationResult supportsPskOnlyHandshake() {
        if (context.getFeatureExtractionResult().getResult(TlsAnalyzedProperty.SUPPORTS_TLS13_PSK)
                == TestResults.TRUE) {
            return ConditionEvaluationResult.enabled("");
        } else {
            return ConditionEvaluationResult.disabled("Does not support PSK handshakes");
        }
    }

    public ConditionEvaluationResult supportsPskDheHandshake() {
        if (context.getFeatureExtractionResult()
                        .getResult(TlsAnalyzedProperty.SUPPORTS_TLS13_PSK_DHE)
                == TestResults.TRUE) {
            return ConditionEvaluationResult.enabled("");
        } else {
            return ConditionEvaluationResult.disabled("Does not support PSK handshakes");
        }
    }

    @AnvilTest
    @MethodCondition(method = "supportsPsk")
    @Tag("new")
    public void isNotLastExtension(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        config.setAddPSKKeyExchangeModesExtension(true);
        adjustPreSharedKeyModes(config);
        WorkflowTrace workflowTrace = getExtensionPositionModifiedTrace(runner, config);

        runner.execute(workflowTrace, config)
                .validateFinal(
                        i -> {
                            Validator.receivedFatalAlert(i);
                            Validator.testAlertDescription(i, AlertDescription.ILLEGAL_PARAMETER);
                        });
    }

    private WorkflowTrace getExtensionPositionModifiedTrace(WorkflowRunner runner, Config config) {
        WorkflowTrace workflowTrace =
                runner.generateWorkflowTraceUntilLastReceivingMessage(
                        WorkflowTraceType.FULL_TLS13_PSK, HandshakeMessageType.SERVER_HELLO);
        ClientHelloMessage resumingHello =
                workflowTrace.getLastSendMessage(ClientHelloMessage.class);
        resumingHello
                .getExtensions()
                .add(
                        resumingHello.getExtensions().size() - 2,
                        new PreSharedKeyExtensionMessage(config));
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));
        return workflowTrace;
    }

    @AnvilTest
    @MethodCondition(method = "supportsPsk")
    @Tag("new")
    public void isLastButDuplicatedExtension(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        setupPskConfig(config);
        WorkflowTrace workflowTrace = getExtensionPositionModifiedTrace(runner, config);

        runner.execute(workflowTrace, config)
                .validateFinal(
                        i -> {
                            Validator.receivedFatalAlert(i);
                            Validator.testAlertDescription(i, AlertDescription.ILLEGAL_PARAMETER);
                        });
    }

    @AnvilTest
    @MethodCondition(method = "supportsPskOnlyHandshake")
    @Tag("new")
    public void respectsKeyExchangeChoicePskOnly(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        config.setAddPSKKeyExchangeModesExtension(true);
        config.setAddPreSharedKeyExtension(true);
        List<PskKeyExchangeMode> pskModes = new LinkedList<>();
        pskModes.add(PskKeyExchangeMode.PSK_KE);
        config.setAddKeyShareExtension(false);
        config.setPSKKeyExchangeModes(pskModes);

        WorkflowTrace workflowTrace =
                runner.generateWorkflowTrace(WorkflowTraceType.FULL_TLS13_PSK);

        runner.execute(workflowTrace, config)
                .validateFinal(
                        i -> {
                            Validator.executedAsPlanned(i);
                            ServerHelloMessage secondServerHello =
                                    (ServerHelloMessage)
                                            WorkflowTraceUtil.getLastReceivedMessage(
                                                    HandshakeMessageType.SERVER_HELLO,
                                                    workflowTrace);
                            if (secondServerHello.containsExtension(ExtensionType.PRE_SHARED_KEY)) {
                                assertFalse(
                                        "Server ignored Key Exchange Mode and sent a Key Share Extension",
                                        secondServerHello.containsExtension(
                                                ExtensionType.KEY_SHARE));
                            }
                        });
    }

    @AnvilTest
    @MethodCondition(method = "supportsPskDheHandshake")
    @Tag("new")
    public void respectsKeyExchangeChoicePskDhe(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        config.setAddPSKKeyExchangeModesExtension(true);
        config.setAddPreSharedKeyExtension(true);
        List<PskKeyExchangeMode> pskModes = new LinkedList<>();
        pskModes.add(PskKeyExchangeMode.PSK_DHE_KE);
        config.setPSKKeyExchangeModes(pskModes);

        WorkflowTrace workflowTrace =
                runner.generateWorkflowTrace(WorkflowTraceType.FULL_TLS13_PSK);

        runner.execute(workflowTrace, config)
                .validateFinal(
                        i -> {
                            Validator.executedAsPlanned(i);
                            ServerHelloMessage secondServerHello =
                                    (ServerHelloMessage)
                                            WorkflowTraceUtil.getLastReceivedMessage(
                                                    HandshakeMessageType.SERVER_HELLO,
                                                    workflowTrace);
                            if (secondServerHello.containsExtension(ExtensionType.PRE_SHARED_KEY)) {
                                assertTrue(
                                        "Server ignored Key Exchange Mode and did not send a Key Share Extension",
                                        secondServerHello.containsExtension(
                                                ExtensionType.KEY_SHARE));
                            }
                        });
    }

    @AnvilTest
    @IncludeParameter("PRF_BITMASK")
    @MethodCondition(method = "supportsPsk")
    public void invalidBinder(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        setupPskConfig(c);
        c.setLimitPsksToOne(true);
        WorkflowTrace workflowTrace =
                runner.generateWorkflowTraceUntilLastReceivingMessage(
                        WorkflowTraceType.FULL_TLS13_PSK, HandshakeMessageType.SERVER_HELLO);
        workflowTrace.addTlsAction(new ReceiveAction());
        byte[] modificationBitmask = parameterCombination.buildBitmask();

        ClientHelloMessage cHello = workflowTrace.getLastSendMessage(ClientHelloMessage.class);
        PreSharedKeyExtensionMessage pskExt =
                cHello.getExtension(PreSharedKeyExtensionMessage.class);
        pskExt.setBinderListBytes(
                Modifiable.xor(modificationBitmask, ExtensionByteLength.PSK_BINDER_LENGTH));

        runner.execute(workflowTrace, c)
                .validateFinal(
                        i -> {
                            WorkflowTrace trace = i.getWorkflowTrace();
                            Validator.receivedFatalAlert(i, false);
                        });
    }

    @AnvilTest
    @MethodCondition(method = "supportsPsk")
    public void noBinder(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        setupPskConfig(config);
        config.setLimitPsksToOne(true);

        WorkflowTrace workflowTrace =
                runner.generateWorkflowTraceUntilLastReceivingMessage(
                        WorkflowTraceType.FULL_TLS13_PSK, HandshakeMessageType.SERVER_HELLO);
        workflowTrace.addTlsAction(new ReceiveAction());

        ClientHelloMessage cHello = workflowTrace.getLastSendMessage(ClientHelloMessage.class);
        PreSharedKeyExtensionMessage pskExt =
                cHello.getExtension(PreSharedKeyExtensionMessage.class);
        pskExt.setBinderListBytes(Modifiable.explicit(new byte[0]));
        pskExt.setBinderListLength(Modifiable.explicit(0));

        runner.execute(workflowTrace, config)
                .validateFinal(
                        i -> {
                            WorkflowTrace trace = i.getWorkflowTrace();
                            Validator.receivedFatalAlert(i, false);
                        });
    }

    @AnvilTest
    @MethodCondition(method = "supportsPsk")
    public void selectedPSKIndexIsWithinOfferedListSize(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
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

        runner.execute(workflowTrace, config)
                .validateFinal(
                        i -> {
                            WorkflowTrace trace = i.getWorkflowTrace();
                            Validator.executedAsPlanned(i);

                            ClientHelloMessage pskClientHello =
                                    (ClientHelloMessage)
                                            WorkflowTraceUtil.getLastSendMessage(
                                                    HandshakeMessageType.CLIENT_HELLO, trace);
                            PreSharedKeyExtensionMessage pskExtension =
                                    pskClientHello.getExtension(PreSharedKeyExtensionMessage.class);
                            int offeredPSKs = pskExtension.getIdentities().size();

                            ServerHelloMessage pskServerHello =
                                    (ServerHelloMessage)
                                            WorkflowTraceUtil.getLastReceivedMessage(
                                                    HandshakeMessageType.SERVER_HELLO, trace);
                            assertTrue(
                                    "PSK Handshake failed - Server did not select as PSK",
                                    pskServerHello.containsExtension(ExtensionType.PRE_SHARED_KEY));
                            int selectedIdentityIndex =
                                    pskServerHello
                                            .getExtension(PreSharedKeyExtensionMessage.class)
                                            .getSelectedIdentity()
                                            .getValue();
                            assertTrue(
                                    "Server set an invalid selected PSK index ("
                                            + selectedIdentityIndex
                                            + " of "
                                            + offeredPSKs
                                            + " )",
                                    selectedIdentityIndex >= 0
                                            && selectedIdentityIndex < offeredPSKs);
                        });
    }

    @AnvilTest
    @MethodCondition(method = "supportsMultipleHdkfHashesAndPsk")
    @Tag("new")
    public void resumeWithCipherWithDifferentHkdfHash(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        setupPskConfig(config);
        WorkflowTrace workflowTrace =
                runner.generateWorkflowTraceUntilLastSendingMessage(
                        WorkflowTraceType.FULL_TLS13_PSK, HandshakeMessageType.FINISHED);
        ClientHelloMessage modifiedClientHello =
                workflowTrace.getLastSendMessage(ClientHelloMessage.class);

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

        runner.execute(workflowTrace, config)
                .validateFinal(
                        i -> {
                            ServerHelloMessage lastHello =
                                    i.getWorkflowTrace()
                                            .getLastReceivedMessage(ServerHelloMessage.class);
                            assertNotNull("Received no ServerHello", lastHello);
                            // the server might abort before sending the 2nd server hello but this
                            // check should always succeed
                            assertFalse(
                                    "Server accepted the PSK of a different HKDF Hash",
                                    lastHello.containsExtension(ExtensionType.PRE_SHARED_KEY));
                        });
    }

    @AnvilTest
    public void sendPskExtensionWithoutPskKeyExchangeModes(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
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

        runner.execute(workflowTrace, config)
                .validateFinal(
                        i -> {
                            if (WorkflowTraceUtil.didReceiveMessage(
                                    HandshakeMessageType.NEW_SESSION_TICKET,
                                    i.getWorkflowTrace())) {
                                Validator.receivedFatalAlert(i);
                            }
                        });
    }

    private void setupPskConfig(Config config) {
        config.setAddPSKKeyExchangeModesExtension(true);
        config.setAddPreSharedKeyExtension(true);
        adjustPreSharedKeyModes(config);
    }
}
