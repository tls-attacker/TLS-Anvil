package de.rub.nds.tlstest.suite.tests.server.tls12.rfc7366;


import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CipherType;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EncryptThenMacExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.annotations.MethodCondition;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.ServerTest;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;

import java.util.Arrays;
import java.util.stream.Collectors;

import static org.junit.Assert.*;

@ServerTest
public class EncThenMacExtension extends Tls12Test {
    public ConditionEvaluationResult blockCipherSupported() {
        if (context.getConfig().getSiteReport().getCipherSuites().stream().anyMatch(i -> {
            try {
                return AlgorithmResolver.getCipherType(i) == CipherType.BLOCK;
            } catch (Exception e) {
                return false;
            }
        })) {
            return ConditionEvaluationResult.enabled("");
        }
        return ConditionEvaluationResult.disabled("Does not support block ciphers");
    }

    public ConditionEvaluationResult supportsNonBlockCipher() {
        if (context.getConfig().getSiteReport().getCipherSuites().stream().anyMatch(i -> {
            try {
                return AlgorithmResolver.getCipherType(i) != CipherType.BLOCK;
            } catch (Exception e) {
                return false;
            }
        })) {
            return ConditionEvaluationResult.enabled("");
        }
        return ConditionEvaluationResult.disabled("Does not support non block cipher");
    }

    @TlsTest(description = "Test if the server supports the encrypt-then-mac extension", securitySeverity = SeverityLevel.MEDIUM)
    @MethodCondition(method = "blockCipherSupported")
    public void supportsEncThenMacExt(WorkflowRunner runner) {
        runner.replaceSupportedCiphersuites = true;
        runner.respectConfigSupportedCiphersuites = true;

        Config c = this.getConfig();
        c.setAddEncryptThenMacExtension(true);

        c.setDefaultClientSupportedCiphersuites(
                Arrays.stream(CipherSuite.values())
                .filter(i -> {
                    try {
                        return AlgorithmResolver.getCipherType(i) == CipherType.BLOCK;
                    } catch (Exception e) {
                        return false;
                    }
                })
                .collect(Collectors.toList())
        );

        WorkflowTrace trace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);

        runner.execute(trace, c).validateFinal(i -> {
            assertTrue("encrypt then mac extension was not negotiated", i.getState().getTlsContext().isExtensionNegotiated(ExtensionType.ENCRYPT_THEN_MAC));
        });
    }


    @RFC(number = 7366, section = "3.  Applying Encrypt-then-MAC")
    @TlsTest(description = "If a server receives an encrypt-then-MAC request extension from a client and then " +
            "selects a stream or Authenticated Encryption with Associated Data (AEAD) ciphersuite, " +
            "it MUST NOT send an encrypt-then-MAC response extension back to the client.",
            securitySeverity = SeverityLevel.LOW, interoperabilitySeverity = SeverityLevel.MEDIUM)
    @MethodCondition(method = "supportsNonBlockCipher")
    public void negotiatesEncThenMacExtOnlyWithBckCiphers(WorkflowRunner runner) {
        runner.replaceSupportedCiphersuites = true;
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

        runner.execute(trace, c).validateFinal(i -> {
            assertFalse("encrypt then mac extension was negotiated, although the selected ciphersuite did not use a block cipher",
                    i.getState().getTlsContext().isExtensionNegotiated(ExtensionType.ENCRYPT_THEN_MAC));
        });
    }
}
