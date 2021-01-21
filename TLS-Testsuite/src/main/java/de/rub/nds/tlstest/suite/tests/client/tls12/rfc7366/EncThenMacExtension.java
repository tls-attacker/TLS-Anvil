/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.client.tls12.rfc7366;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CipherType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EncryptThenMacExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.ClientTest;
import de.rub.nds.tlstest.framework.annotations.DynamicValueConstraints;
import de.rub.nds.tlstest.framework.annotations.MethodCondition;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.ScopeLimitations;
import de.rub.nds.tlstest.framework.annotations.TestDescription;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.annotations.categories.Alert;
import de.rub.nds.tlstest.framework.annotations.categories.Compliance;
import de.rub.nds.tlstest.framework.annotations.categories.Crypto;
import de.rub.nds.tlstest.framework.annotations.categories.Handshake;
import de.rub.nds.tlstest.framework.annotations.categories.Interoperability;
import de.rub.nds.tlstest.framework.annotations.categories.Security;
import de.rub.nds.tlstest.framework.coffee4j.model.ModelFromScope;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.DerivationType;
import de.rub.nds.tlstest.framework.model.ModelType;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;


import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@ClientTest
public class EncThenMacExtension extends Tls12Test {

    public ConditionEvaluationResult supportsExtension() {
        return context.getReceivedClientHelloMessage().getExtension(EncryptThenMacExtensionMessage.class) == null
                ? ConditionEvaluationResult.disabled("Target does not support EncThenMacExt") : ConditionEvaluationResult.enabled("");
    }

    @Test
    @Security(SeverityLevel.MEDIUM)
    //TODO: if we add more extension tests in the future, we could add
    //an OptionalFeatures category
    @TestDescription("Test if the client supports the encrypt-then-mac extension")
    @Crypto(SeverityLevel.MEDIUM)
    public void supportsEncThenMacExt() {
        EncryptThenMacExtensionMessage ext = context.getReceivedClientHelloMessage().getExtension(EncryptThenMacExtensionMessage.class);
        assertNotNull("Client does not support encrypt-then-mac extension", ext);
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

    @RFC(number = 7366, section = "3.  Applying Encrypt-then-MAC")
    @TlsTest(description = "If a server receives an encrypt-then-MAC request extension from a client and then "
            + "selects a stream or Authenticated Encryption with Associated Data (AEAD) ciphersuite, "
            + "it MUST NOT send an encrypt-then-MAC response extension back to the client.")
    @MethodCondition(method = "supportsExtension")
    @DynamicValueConstraints(affectedTypes = DerivationType.CIPHERSUITE, methods = "isNotBlockCipher")
    @ScopeLimitations(DerivationType.INCLUDE_ENCRYPT_THEN_MAC_EXTENSION)
    @Interoperability(SeverityLevel.MEDIUM)
    @Compliance(SeverityLevel.MEDIUM)
    @Handshake(SeverityLevel.MEDIUM)
    @Alert(SeverityLevel.MEDIUM)
    public void sendEncThenMacExtWithNonBlockCiphers(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        c.setAddEncryptThenMacExtension(true);

        WorkflowTrace trace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);

        runner.execute(trace, c).validateFinal(i -> {
            assertFalse("Workflow executed as expected", i.getWorkflowTrace().executedAsPlanned());
            Validator.receivedFatalAlert(i, false);
        });
    }
    
    @TlsTest(description = "Test if the client can complete the handshake if encrypt-then-MAC is negotiated")
    @MethodCondition(method = "supportsExtension")
    @ModelFromScope(baseModel = ModelType.CERTIFICATE)
    @DynamicValueConstraints(affectedTypes = DerivationType.CIPHERSUITE, methods = "isBlockCipher")
    @ScopeLimitations(DerivationType.INCLUDE_ENCRYPT_THEN_MAC_EXTENSION)
    @Interoperability(SeverityLevel.HIGH)
    @Compliance(SeverityLevel.HIGH)
    @Handshake(SeverityLevel.MEDIUM)
    public void encryptThenMacTest(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        c.setAddEncryptThenMacExtension(true);
        WorkflowTrace trace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        
        runner.execute(trace, c).validateFinal(Validator::executedAsPlanned);
    }
}
