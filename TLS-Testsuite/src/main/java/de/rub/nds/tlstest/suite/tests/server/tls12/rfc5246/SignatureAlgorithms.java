/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.server.tls12.rfc5246;

import static org.junit.Assert.assertEquals;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.ExcludeParameter;
import de.rub.nds.anvilcore.annotation.MethodCondition;
import de.rub.nds.anvilcore.annotation.ServerTest;
import de.rub.nds.anvilcore.teststate.AnvilTestCase;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.HashAlgorithm;
import de.rub.nds.tlsattacker.core.constants.SignatureAlgorithm;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SignatureAndHashAlgorithmsExtensionMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceResultUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;

@ServerTest
public class SignatureAlgorithms extends Tls12Test {

    private WorkflowTrace getWorkflowFor(Config c) {

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                new SendAction(new ClientHelloMessage(c)),
                new ReceiveTillAction(new ServerHelloDoneMessage()));
        return workflowTrace;
    }

    private boolean supported(String filter) {
        List<CipherSuite> cipherSuites =
                new ArrayList<>(context.getFeatureExtractionResult().getCipherSuites());
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

    @AnvilTest(id = "5246-ZdnCWL4k5G")
    @MethodCondition(method = "dssCiphersuitesSupported")
    public void dssNoSignatureAlgorithmsExtension(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);
        c.setAddSignatureAndHashAlgorithmsExtension(false);

        WorkflowTrace workflowTrace = getWorkflowFor(c);

        State state = runner.execute(workflowTrace, c);

        Validator.executedAsPlanned(state, testCase);

        assertEquals(
                SignatureAlgorithm.DSA,
                state.getTlsContext()
                        .getSelectedSignatureAndHashAlgorithm()
                        .getSignatureAlgorithm());
        assertEquals(
                HashAlgorithm.SHA1,
                state.getTlsContext().getSelectedSignatureAndHashAlgorithm().getHashAlgorithm());
    }

    @AnvilTest(id = "5246-MjFVuYUzfF")
    @MethodCondition(method = "ecdsaCiphersuitesSupported")
    public void ecdsaNoSignatureAlgorithmsExtension(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);
        c.setAddSignatureAndHashAlgorithmsExtension(false);

        WorkflowTrace workflowTrace = getWorkflowFor(c);

        State state = runner.execute(workflowTrace, c);

        Validator.executedAsPlanned(state, testCase);

        assertEquals(
                SignatureAlgorithm.ECDSA,
                state.getTlsContext()
                        .getSelectedSignatureAndHashAlgorithm()
                        .getSignatureAlgorithm());
        assertEquals(
                HashAlgorithm.SHA1,
                state.getTlsContext().getSelectedSignatureAndHashAlgorithm().getHashAlgorithm());
    }

    @AnvilTest(id = "5246-gnRCzTtN6q")
    // This requirement also applies to older versions
    public void includeUnknownSignatureAndHashAlgorithm(
            AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);
        c.setAddSignatureAndHashAlgorithmsExtension(true);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        ClientHelloMessage clientHello =
                (ClientHelloMessage)
                        WorkflowTraceResultUtil.getFirstSentMessage(
                                workflowTrace, HandshakeMessageType.CLIENT_HELLO);
        SignatureAndHashAlgorithmsExtensionMessage algorithmsExtension =
                clientHello.getExtension(SignatureAndHashAlgorithmsExtensionMessage.class);
        algorithmsExtension.setSignatureAndHashAlgorithms(
                Modifiable.insert(new byte[] {(byte) 0xfe, 0x44}, 0));

        State state = runner.execute(workflowTrace, c);
        Validator.executedAsPlanned(state, testCase);
    }

    @AnvilTest(id = "5246-52fQFPB85j")
    @ExcludeParameter("INCLUDE_GREASE_SIG_HASH_ALGORITHMS")
    public void offerManyAlgorithms(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);

        // add pseudo algorithms to reach 58 which is the number of all defined values
        // and grease values
        int realAlgorithms = c.getDefaultClientSupportedSignatureAndHashAlgorithms().size();
        byte[] explicitAlgorithms = new byte[58 * 2];
        int y = 0;
        for (int i = 0; i < 58 * 2; i = i + 2) {
            if (i < (58 - realAlgorithms) * 2) {
                explicitAlgorithms[i] = (byte) 0x0A;
                explicitAlgorithms[i + 1] = (byte) i;
            } else {
                explicitAlgorithms[i] =
                        c.getDefaultClientSupportedSignatureAndHashAlgorithms()
                                .get(y)
                                .getByteValue()[0];
                explicitAlgorithms[i + 1] =
                        c.getDefaultClientSupportedSignatureAndHashAlgorithms()
                                .get(y)
                                .getByteValue()[1];
                y++;
            }
        }
        ClientHelloMessage clientHello =
                (ClientHelloMessage)
                        WorkflowTraceResultUtil.getFirstSentMessage(
                                workflowTrace, HandshakeMessageType.CLIENT_HELLO);
        clientHello
                .getExtension(SignatureAndHashAlgorithmsExtensionMessage.class)
                .setSignatureAndHashAlgorithms(Modifiable.explicit(explicitAlgorithms));
        State state = runner.execute(workflowTrace, c);
        Validator.executedAsPlanned(state, testCase);
    }
}
