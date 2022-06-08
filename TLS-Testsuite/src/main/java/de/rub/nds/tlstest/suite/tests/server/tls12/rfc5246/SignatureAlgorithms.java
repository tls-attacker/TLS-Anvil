/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * Copyright 2022 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.server.tls12.rfc5246;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.HashAlgorithm;
import de.rub.nds.tlsattacker.core.constants.SignatureAlgorithm;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SignatureAndHashAlgorithmsExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.annotations.MethodCondition;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.ScopeLimitations;
import de.rub.nds.tlstest.framework.annotations.ServerTest;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.annotations.categories.ComplianceCategory;
import de.rub.nds.tlstest.framework.annotations.categories.HandshakeCategory;
import de.rub.nds.tlstest.framework.annotations.categories.InteroperabilityCategory;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.DerivationType;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;

import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertEquals;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@ServerTest
@RFC(number = 5246, section = "7.4.1.4.1. Signature Algorithms")
public class SignatureAlgorithms extends Tls12Test {

    private WorkflowTrace getWorkflowFor(Config c) {

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                new SendAction(new ClientHelloMessage(c)),
                new ReceiveTillAction(new ServerHelloDoneMessage())
        );
        return workflowTrace;
    }

    private boolean supported(String filter) {
        List<CipherSuite> cipherSuites = new ArrayList<>(context.getSiteReport().getCipherSuites());
        cipherSuites.removeIf(i -> !i.toString().contains(filter));
        return cipherSuites.size() > 0;
    }

    private ConditionEvaluationResult rsaCiphersuitesSupported() {
        if (supported("_RSA")) {
            return ConditionEvaluationResult.enabled("");
        }
        return ConditionEvaluationResult.disabled("No RSA signature ciphersuites supported");
    }

    private ConditionEvaluationResult dssCiphersuitesSupported() {
        if (supported("_DSS")) {
            return ConditionEvaluationResult.enabled("");
        }
        return ConditionEvaluationResult.disabled("No DSA signature ciphersuites supported");
    }

    private ConditionEvaluationResult ecdsaCiphersuitesSupported() {
        if (supported("_ECDSA")) {
            return ConditionEvaluationResult.enabled("");
        }
        return ConditionEvaluationResult.disabled("No ECDSA signature ciphersuites supported");
    }

    @TlsTest(description = "If the client does not send the signature_algorithms extension, the server MUST do the following:" +
            "[...]If the negotiated key exchange algorithm is one of (DHE_DSS, DH_DSS), " +
            "behave as if the client had sent the value {sha1,dsa}.")
    @MethodCondition(method = "dssCiphersuitesSupported")
    @InteroperabilityCategory(SeverityLevel.MEDIUM)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.MEDIUM)
    public void dssNoSignatureAlgorithmsExtension(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        c.setAddSignatureAndHashAlgorithmsExtension(false);

        WorkflowTrace workflowTrace = getWorkflowFor(c);

        runner.execute(workflowTrace, c).validateFinal(i -> {
            Validator.executedAsPlanned(i);

            assertEquals(SignatureAlgorithm.DSA, i.getState().getTlsContext().getSelectedSignatureAndHashAlgorithm().getSignatureAlgorithm());
            assertEquals(HashAlgorithm.SHA1, i.getState().getTlsContext().getSelectedSignatureAndHashAlgorithm().getHashAlgorithm());
        });
    }

    @TlsTest(description = "If the client does not send the signature_algorithms extension, the server MUST do the following:" +
            "[...]If the negotiated key exchange algorithm is one of (DHE_DSS, DH_DSS), " +
            "behave as if the client had sent the value {sha1,dsa}.")
    @MethodCondition(method = "ecdsaCiphersuitesSupported")
    @InteroperabilityCategory(SeverityLevel.MEDIUM)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.MEDIUM)
    public void ecdsaNoSignatureAlgorithmsExtension(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        c.setAddSignatureAndHashAlgorithmsExtension(false);

        WorkflowTrace workflowTrace = getWorkflowFor(c);

        runner.execute(workflowTrace, c).validateFinal(i -> {
            Validator.executedAsPlanned(i);

            assertEquals(SignatureAlgorithm.ECDSA, i.getState().getTlsContext().getSelectedSignatureAndHashAlgorithm().getSignatureAlgorithm());
            assertEquals(HashAlgorithm.SHA1, i.getState().getTlsContext().getSelectedSignatureAndHashAlgorithm().getHashAlgorithm());
        });
    }
    
    @TlsTest(description = "Each SignatureAndHashAlgorithm value lists a single hash/signature " +
        "pair that the client is willing to verify.  The values are indicated " +
        "in descending order of preference. [...]" + 
        "Because not all signature algorithms and hash algorithms may be " +
        "accepted by an implementation (e.g., DSA with SHA-1, but not " +
        "SHA-256), algorithms here are listed in pairs.")
    //This requirement also applies to older versions
    @RFC(number = 5246, section = "7.4.1.4.1.  Signature Algorithms")
    @InteroperabilityCategory(SeverityLevel.HIGH)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    public void includeUnknownSignatureAndHashAlgorithm(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        c.setAddSignatureAndHashAlgorithmsExtension(true);
        
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        ClientHelloMessage clientHello = (ClientHelloMessage) WorkflowTraceUtil.getFirstSendMessage(HandshakeMessageType.CLIENT_HELLO, workflowTrace);
        SignatureAndHashAlgorithmsExtensionMessage algorithmsExtension = clientHello.getExtension(SignatureAndHashAlgorithmsExtensionMessage.class);
        algorithmsExtension.setSignatureAndHashAlgorithms(Modifiable.insert(new byte[]{(byte)0xfe, 0x44}, 0));
        
        runner.execute(workflowTrace, c).validateFinal(Validator::executedAsPlanned);
    }
    
    @TlsTest(description = "Send a ClientHello that offers many SignatureAndHash algorithms")
    @ScopeLimitations(DerivationType.INCLUDE_GREASE_SIG_HASH_ALGORITHMS)
    @InteroperabilityCategory(SeverityLevel.HIGH)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    public void offerManyAlgorithms(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        
        //add pseudo algorithms to reach 58 which is the number of all defined values
        //and grease values
        int realAlgorithms = c.getDefaultClientSupportedSignatureAndHashAlgorithms().size();
        byte[] explicitAlgorithms = new byte[58 * 2];
        int y = 0;
        for(int i = 0; i < 58 * 2; i = i + 2) {
            if(i < (58 - realAlgorithms) * 2) {
                explicitAlgorithms[i] = (byte) 0x0A;
                explicitAlgorithms[i+1] = (byte) i;
            } else {
                explicitAlgorithms[i] = c.getDefaultClientSupportedSignatureAndHashAlgorithms().get(y).getByteValue()[0];
                explicitAlgorithms[i + 1] = c.getDefaultClientSupportedSignatureAndHashAlgorithms().get(y).getByteValue()[1];
                y++;
            }
            
        }
        ClientHelloMessage clientHello = (ClientHelloMessage) WorkflowTraceUtil.getFirstSendMessage(HandshakeMessageType.CLIENT_HELLO, workflowTrace);
        clientHello.getExtension(SignatureAndHashAlgorithmsExtensionMessage.class).setSignatureAndHashAlgorithms(Modifiable.explicit(explicitAlgorithms));
        runner.execute(workflowTrace, c).validateFinal(Validator::executedAsPlanned);
    }
}
