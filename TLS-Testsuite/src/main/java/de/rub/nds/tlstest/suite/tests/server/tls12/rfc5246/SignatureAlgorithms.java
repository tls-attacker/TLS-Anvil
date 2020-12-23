/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
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
import de.rub.nds.tlstest.framework.annotations.ServerTest;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.annotations.categories.Interoperability;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
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

    @TlsTest(description = "If the client does not send the signature_algorithms extension, the server MUST do the following:\n" +
            "If the negotiated key exchange algorithm is one of (RSA, DHE_RSA, DH_RSA, RSA_PSK, ECDH_RSA, ECDHE_RSA), " +
            "behave as if client had sent the value {sha1,rsa}.")
    @Interoperability(SeverityLevel.MEDIUM)
    @MethodCondition(method = "rsaCiphersuitesSupported")
    @KeyExchange(supported = KeyExchangeType.ALL12, requiresServerKeyExchMsg = true)
    public void rsaNoSignatureAlgorithmsExtension(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        c.setAddSignatureAndHashAlgorithmsExtension(false);

        WorkflowTrace workflowTrace = getWorkflowFor(c);

        runner.execute(workflowTrace, c).validateFinal(i -> {
            Validator.executedAsPlanned(i);

            assertEquals(SignatureAlgorithm.RSA, i.getState().getTlsContext().getSelectedSignatureAndHashAlgorithm().getSignatureAlgorithm());
            ServerKeyExchangeMessage skx = i.getWorkflowTrace().getFirstReceivedMessage(ServerKeyExchangeMessage.class);
            SignatureAndHashAlgorithm sigHashAlg = SignatureAndHashAlgorithm.getSignatureAndHashAlgorithm(skx.getSignatureAndHashAlgorithm().getValue());
            assertEquals(HashAlgorithm.SHA1, sigHashAlg.getHashAlgorithm());
        });

    }

    @TlsTest(description = "If the client does not send the signature_algorithms extension, the server MUST do the following:\n" +
            "If the negotiated key exchange algorithm is one of (DHE_DSS, DH_DSS), " +
            "behave as if the client had sent the value {sha1,dsa}.")
    @Interoperability(SeverityLevel.MEDIUM)
    @MethodCondition(method = "dssCiphersuitesSupported")
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

    @TlsTest(description = "If the client does not send the signature_algorithms extension, the server MUST do the following:\n" +
            "If the negotiated key exchange algorithm is one of (ECDH_ECDSA, ECDHE_ECDSA), " +
            "behave as if the client had sent value {sha1,ecdsa}.")
    @Interoperability(SeverityLevel.MEDIUM)
    @MethodCondition(method = "ecdsaCiphersuitesSupported")
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
    
    @TlsTest(description = "Perform a Handshake where the Signature and Hash Algorithms Extension contains an additional, undefined algorithm")
    @Interoperability(SeverityLevel.HIGH)
    public void includeUnknownSignatureAndHashAlgorithm(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        c.setAddSignatureAndHashAlgorithmsExtension(true);
        
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        ClientHelloMessage clientHello = (ClientHelloMessage) WorkflowTraceUtil.getFirstSendMessage(HandshakeMessageType.CLIENT_HELLO, workflowTrace);
        SignatureAndHashAlgorithmsExtensionMessage algorithmsExtension = clientHello.getExtension(SignatureAndHashAlgorithmsExtensionMessage.class);
        algorithmsExtension.setSignatureAndHashAlgorithms(Modifiable.insert(new byte[]{(byte)0xfe, 0x44}, 0));
        
        runner.execute(workflowTrace, c).validateFinal(Validator::executedAsPlanned);
    }
}
