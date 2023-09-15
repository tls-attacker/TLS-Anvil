/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.client.tls12.rfc7366;

import static org.junit.Assert.assertFalse;

import de.rub.nds.anvilcore.annotation.*;
import de.rub.nds.anvilcore.coffee4j.model.ModelFromScope;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CipherType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EncryptThenMacExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.EnforcedSenderRestriction;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@ClientTest
public class EncThenMacExtension extends Tls12Test {

    public ConditionEvaluationResult supportsExtension() {
        return context.getReceivedClientHelloMessage()
                                .getExtension(EncryptThenMacExtensionMessage.class)
                        == null
                ? ConditionEvaluationResult.disabled("Target does not support Encrypt-Then-Mac")
                : ConditionEvaluationResult.enabled("");
    }

    public boolean isNotBlockCipher(CipherSuite cipherSuite) {
        try {
            return AlgorithmResolver.getCipherType(cipherSuite) != CipherType.BLOCK;
        } catch (Exception e) {
            return false;
        }
    }

    public boolean isBlockCipher(CipherSuite cipherSuite) {
        try {
            return AlgorithmResolver.getCipherType(cipherSuite) == CipherType.BLOCK;
        } catch (Exception e) {
            return false;
        }
    }

    @AnvilTest
    @MethodCondition(method = "supportsExtension")
    @DynamicValueConstraints(affectedIdentifiers = "CIPHER_SUITE", methods = "isNotBlockCipher")
    @ExcludeParameter("INCLUDE_ENCRYPT_THEN_MAC_EXTENSION")
    @EnforcedSenderRestriction
    public void sendEncThenMacExtWithNonBlockCiphers(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        c.setAddEncryptThenMacExtension(true);

        WorkflowTrace trace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);

        runner.execute(trace, c)
                .validateFinal(
                        i -> {
                            assertFalse(
                                    "Workflow executed as expected",
                                    i.getWorkflowTrace().executedAsPlanned());
                            Validator.receivedFatalAlert(i, false);
                        });
    }

    @AnvilTest
    @MethodCondition(method = "supportsExtension")
    @ModelFromScope(modelType = "CERTIFICATE")
    @DynamicValueConstraints(affectedIdentifiers = "CIPHER_SUITE", methods = "isBlockCipher")
    @ExcludeParameter("INCLUDE_ENCRYPT_THEN_MAC_EXTENSION")
    public void encryptThenMacTest(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        c.setAddEncryptThenMacExtension(true);
        WorkflowTrace trace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);

        runner.execute(trace, c).validateFinal(Validator::executedAsPlanned);
    }
}
