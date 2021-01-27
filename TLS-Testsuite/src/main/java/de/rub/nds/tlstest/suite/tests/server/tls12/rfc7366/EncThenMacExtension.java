/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.server.tls12.rfc7366;


import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CipherType;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.annotations.DynamicValueConstraints;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.ScopeLimitations;
import de.rub.nds.tlstest.framework.annotations.ServerTest;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.annotations.categories.AlertCategory;
import de.rub.nds.tlstest.framework.annotations.categories.ComplianceCategory;
import de.rub.nds.tlstest.framework.annotations.categories.CryptoCategory;
import de.rub.nds.tlstest.framework.annotations.categories.DeprecatedFeatureCategory;
import de.rub.nds.tlstest.framework.annotations.categories.HandshakeCategory;
import de.rub.nds.tlstest.framework.annotations.categories.InteroperabilityCategory;
import de.rub.nds.tlstest.framework.annotations.categories.MessageStructureCategory;
import de.rub.nds.tlstest.framework.annotations.categories.SecurityCategory;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.constants.TestEndpointType;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.DerivationType;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;
import de.rub.nds.tlstest.framework.annotations.categories.RecordLayerCategory;

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
        if(context.getSiteReport().getSupportedExtensions() != null && context.getSiteReport().getSupportedExtensions().contains(ExtensionType.ENCRYPT_THEN_MAC)) {
            return ConditionEvaluationResult.enabled("The Extension can be tested");
        }
        return ConditionEvaluationResult.disabled("Encrypt-Then-Mac Extension not supported");
    }

    @TlsTest(description = "Test if the server supports the encrypt-then-mac extension")
    @DynamicValueConstraints(affectedTypes=DerivationType.CIPHERSUITE, methods="isBlockCipher")
    @ScopeLimitations(DerivationType.INCLUDE_ENCRYPT_THEN_MAC_EXTENSION)
    @HandshakeCategory(SeverityLevel.INFORMATIONAL)
    @ComplianceCategory(SeverityLevel.INFORMATIONAL)
    @CryptoCategory(SeverityLevel.INFORMATIONAL)
    @RecordLayerCategory(SeverityLevel.LOW)
    @SecurityCategory(SeverityLevel.LOW)
    public void supportsEncThenMacExt(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        c.setAddEncryptThenMacExtension(true);
        
        WorkflowTrace trace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);

        runner.execute(trace, c).validateFinal(i -> {
            assertTrue("encrypt then mac extension was not negotiated", i.getState().getTlsContext().isExtensionNegotiated(ExtensionType.ENCRYPT_THEN_MAC));
        });
    }


    @RFC(number = 7366, section = "3.  Applying Encrypt-then-MAC")
    @TlsTest(description = "If a server receives an encrypt-then-MAC request extension from a client and then " +
            "selects a stream or Authenticated Encryption with Associated Data (AEAD) ciphersuite, " +
            "it MUST NOT send an encrypt-then-MAC response extension back to the client.")
    @DynamicValueConstraints(affectedTypes=DerivationType.CIPHERSUITE, methods="isNotBlockCipher")
    @ScopeLimitations(DerivationType.INCLUDE_ENCRYPT_THEN_MAC_EXTENSION)
    @InteroperabilityCategory(SeverityLevel.HIGH)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    @AlertCategory(SeverityLevel.HIGH)
    public void negotiatesEncThenMacExtOnlyWithBlockCiphers(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        c.setAddEncryptThenMacExtension(true);

        WorkflowTrace trace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);

        runner.execute(trace, c).validateFinal(i -> {
            assertFalse("encrypt then mac extension was negotiated, although the selected ciphersuite did not use a block cipher",
                    i.getState().getTlsContext().isExtensionNegotiated(ExtensionType.ENCRYPT_THEN_MAC));
        });
    }
}
