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

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.IncludeParameter;
import de.rub.nds.anvilcore.annotation.MethodCondition;
import de.rub.nds.anvilcore.annotation.ServerTest;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HKDFAlgorithm;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.PskKeyExchangeMode;
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
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.categories.AlertCategory;
import de.rub.nds.tlstest.framework.annotations.categories.ComplianceCategory;
import de.rub.nds.tlstest.framework.annotations.categories.CryptoCategory;
import de.rub.nds.tlstest.framework.annotations.categories.HandshakeCategory;
import de.rub.nds.tlstest.framework.annotations.categories.InteroperabilityCategory;
import de.rub.nds.tlstest.framework.annotations.categories.SecurityCategory;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.derivationParameter.CipherSuiteDerivation;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@ServerTest
@RFC(number = 8446, section = "4.2.11 Pre-Shared Key Extension")
@Disabled // disabled for development, because it fails on windows
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

    @AnvilTest(
            description =
                    "The \"pre_shared_key\" extension MUST be the last extension "
                            + "in the ClientHello (this facilitates implementation as described below). "
                            + "Servers MUST check that it is the last extension and otherwise fail "
                            + "the handshake with an \"illegal_parameter\" alert.")
    @InteroperabilityCategory(SeverityLevel.MEDIUM)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    @SecurityCategory(SeverityLevel.HIGH)
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

    @AnvilTest(
            description =
                    "The \"pre_shared_key\" extension MUST be the last extension "
                            + "in the ClientHello (this facilitates implementation as described below). "
                            + "Servers MUST check that it is the last extension and otherwise fail "
                            + "the handshake with an \"illegal_parameter\" alert.")
    @InteroperabilityCategory(SeverityLevel.MEDIUM)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @SecurityCategory(SeverityLevel.HIGH)
    @ComplianceCategory(SeverityLevel.HIGH)
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

    @AnvilTest(
            description =
                    "If the server selects a PSK, then it MUST also select a key "
                            + "establishment mode from the set indicated by the client's "
                            + "\"psk_key_exchange_modes\" extension (at present, PSK alone or with "
                            + "(EC)DHE). [...]"
                            + "[Servers] MUST NOT send a "
                            + "KeyShareEntry when using the \"psk_ke\" PskKeyExchangeMode. [...]"
                            + "PSK-only key establishment.  In this mode, the server "
                            + "MUST NOT supply a \"key_share\" value.")
    @RFC(
            number = 8446,
            section =
                    "4.1.1.  Cryptographic Negotiation, 4.2.8. Key Share, and 4.2.9. Pre-Shared Key Exchange Modes")
    @InteroperabilityCategory(SeverityLevel.MEDIUM)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
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

    @AnvilTest(
            description =
                    "If the server selects a PSK, then it MUST also select a key "
                            + "establishment mode from the set indicated by the client's "
                            + "\"psk_key_exchange_modes\" extension (at present, PSK alone or with "
                            + "(EC)DHE). [...] "
                            + "Servers MUST NOT select a key "
                            + "exchange mode that is not listed by the client. [...]"
                            + "PSK with (EC)DHE key establishment.  In this mode, the "
                            + "client and server MUST supply \"key_share\" values as described in "
                            + "Section 4.2.8.")
    @RFC(
            number = 8446,
            section = "4.1.1.  Cryptographic Negotiation and 4.2.9. Pre-Shared Key Exchange Modes")
    @InteroperabilityCategory(SeverityLevel.MEDIUM)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
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

    @AnvilTest(
            description =
                    "Prior to accepting PSK key establishment, the server MUST validate "
                            + "the corresponding binder value (see Section 4.2.11.2 below).  If this "
                            + "value is not present or does not validate, the server MUST abort the "
                            + "handshake.")
    @IncludeParameter("PRF_BITMASK")
    @MethodCondition(method = "supportsPsk")
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    @CryptoCategory(SeverityLevel.CRITICAL)
    @SecurityCategory(SeverityLevel.CRITICAL)
    @AlertCategory(SeverityLevel.LOW)
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

    @AnvilTest(
            description =
                    "Prior to accepting PSK key establishment, the server MUST validate "
                            + "the corresponding binder value")
    @MethodCondition(method = "supportsPsk")
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    @CryptoCategory(SeverityLevel.CRITICAL)
    @SecurityCategory(SeverityLevel.CRITICAL)
    @AlertCategory(SeverityLevel.LOW)
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

    @AnvilTest(
            description =
                    "Clients MUST verify that the server’s selected_identity is within the "
                            + "range supplied by the client")
    @MethodCondition(method = "supportsPsk")
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    @SecurityCategory(SeverityLevel.HIGH)
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

    @AnvilTest(
            description =
                    "Any ticket MUST only be resumed with a cipher suite that has the same KDF hash algorithm as that used to establish the original connection.")
    @RFC(number = 8446, section = "4.6.1.  New Session Ticket Message")
    @MethodCondition(method = "supportsMultipleHdkfHashesAndPsk")
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
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

    @AnvilTest(
            description =
                    "If clients offer "
                            + "\"pre_shared_key\" without a \"psk_key_exchange_modes\" extension, "
                            + "servers MUST abort the handshake.")
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.MEDIUM)
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
