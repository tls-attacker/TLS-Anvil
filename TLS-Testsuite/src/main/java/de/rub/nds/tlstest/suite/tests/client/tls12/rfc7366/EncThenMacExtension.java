package de.rub.nds.tlstest.suite.tests.client.tls12.rfc7366;


import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CipherType;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EncryptThenMacExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.ClientTest;
import de.rub.nds.tlstest.framework.annotations.MethodCondition;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;

import java.util.Arrays;
import java.util.stream.Collectors;

import static org.junit.Assert.assertNotNull;

@ClientTest
public class EncThenMacExtension extends Tls12Test {
    private boolean supportsBlockCiphers() {
        if (context.getSiteReport().getCipherSuites().stream().anyMatch(i -> {
            try {
                return AlgorithmResolver.getCipherType(i) != CipherType.BLOCK;
            } catch (Exception e) {
                return false;
            }
        })) {
            return true;
        }
        return false;
    }

    public ConditionEvaluationResult supportsNonBlockCipher() {
        ConditionEvaluationResult supportsE = supportsExtension();
        if (supportsE.isDisabled()) return supportsE;
        return supportsBlockCiphers() ? ConditionEvaluationResult.enabled("") : ConditionEvaluationResult.disabled("Does not support block ciphers");
    }

    public ConditionEvaluationResult supportsExtension() {
        return context.getReceivedClientHelloMessage().getExtension(EncryptThenMacExtensionMessage.class) == null ?
                ConditionEvaluationResult.disabled("Target does not support EncThenMacExt") : ConditionEvaluationResult.enabled("");
    }

    @TlsTest(description = "Test if the client supports the encrypt-then-mac extension", securitySeverity = SeverityLevel.MEDIUM)
    public void supportsEncThenMacExt() {
        EncryptThenMacExtensionMessage ext = context.getReceivedClientHelloMessage().getExtension(EncryptThenMacExtensionMessage.class);
        assertNotNull("Client does not support encrypt-then-mac extension", ext);
    }

    @RFC(number = 7366, section = "3.  Applying Encrypt-then-MAC")
    @TlsTest(description = "If a server receives an encrypt-then-MAC request extension from a client and then " +
            "selects a stream or Authenticated Encryption with Associated Data (AEAD) ciphersuite, " +
            "it MUST NOT send an encrypt-then-MAC response extension back to the client.",
            securitySeverity = SeverityLevel.LOW, interoperabilitySeverity = SeverityLevel.MEDIUM)
    @MethodCondition(method = "supportsNonBlockCipher")
    public void sendEncThenMacExtWithNonBlockCiphers(WorkflowRunner runner) {
        runner.replaceSelectedCiphersuite = true;
        runner.respectConfigSupportedCiphersuites = true;

        Config c = this.getConfig();
        c.setAddEncryptThenMacExtension(true);

        c.setDefaultClientSupportedCiphersuites(
                Arrays.stream(CipherSuite.values())
                .filter(i -> {
                    try {
                        return AlgorithmResolver.getCipherType(i) != CipherType.BLOCK;
                    } catch (Exception e) {
                        return false;
                    }
                })
                .collect(Collectors.toList())
        );

        WorkflowTrace trace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        trace.addTlsActions(new ReceiveAction(new AlertMessage()));

        runner.execute(trace, c).validateFinal(Validator::receivedFatalAlert);
    }
}
