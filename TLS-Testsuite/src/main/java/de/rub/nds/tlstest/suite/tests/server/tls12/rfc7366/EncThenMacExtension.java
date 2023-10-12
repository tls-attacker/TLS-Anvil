/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.server.tls12.rfc7366;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import de.rub.nds.anvilcore.annotation.*;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CipherType;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.ServerFeatureExtractionResult;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@ServerTest
public class EncThenMacExtension extends Tls12Test {

    public boolean isBlockCipher(CipherSuite cipherSuite) {
        try {
            return AlgorithmResolver.getCipherType(cipherSuite) == CipherType.BLOCK;
        } catch (Exception e) {
            return false;
        }
    }

    public boolean isNotBlockCipher(CipherSuite cipherSuite) {
        try {
            return AlgorithmResolver.getCipherType(cipherSuite) != CipherType.BLOCK;
        } catch (Exception e) {
            return false;
        }
    }

    public ConditionEvaluationResult targetCanBeTested() {
        ServerFeatureExtractionResult extractionResult =
                (ServerFeatureExtractionResult) context.getFeatureExtractionResult();
        if (extractionResult.getNegotiableExtensions() != null
                && extractionResult
                        .getNegotiableExtensions()
                        .contains(ExtensionType.ENCRYPT_THEN_MAC)) {
            return ConditionEvaluationResult.enabled("The Extension can be tested");
        }
        return ConditionEvaluationResult.disabled("Encrypt-Then-Mac Extension not supported");
    }

    @AnvilTest(id = "7366-rFjsKGrqCe")
    @DynamicValueConstraints(affectedIdentifiers = "CIPHER_SUITE", methods = "isBlockCipher")
    @ExcludeParameter("INCLUDE_ENCRYPT_THEN_MAC_EXTENSION")
    @MethodCondition(method = "targetCanBeTested")
    public void negotiatesEncThenMacExt(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        c.setAddEncryptThenMacExtension(true);

        WorkflowTrace trace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);

        runner.execute(trace, c)
                .validateFinal(
                        i -> {
                            assertTrue(
                                    "Encrypt then mac extension was not negotiated",
                                    i.getState()
                                            .getTlsContext()
                                            .isExtensionNegotiated(ExtensionType.ENCRYPT_THEN_MAC));
                        });
    }

    @AnvilTest(id = "7366-HSEGiXELMF")
    @DynamicValueConstraints(affectedIdentifiers = "CIPHER_SUITE", methods = "isNotBlockCipher")
    @ExcludeParameter("INCLUDE_ENCRYPT_THEN_MAC_EXTENSION")
    @MethodCondition(method = "targetCanBeTested")
    public void negotiatesEncThenMacExtOnlyWithBlockCiphers(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        c.setAddEncryptThenMacExtension(true);

        WorkflowTrace trace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);

        runner.execute(trace, c)
                .validateFinal(
                        i -> {
                            assertFalse(
                                    "Encrypt then mac extension was negotiated, although the selected ciphersuite did not use a block cipher",
                                    i.getState()
                                            .getTlsContext()
                                            .isExtensionNegotiated(ExtensionType.ENCRYPT_THEN_MAC));
                        });
    }
}
