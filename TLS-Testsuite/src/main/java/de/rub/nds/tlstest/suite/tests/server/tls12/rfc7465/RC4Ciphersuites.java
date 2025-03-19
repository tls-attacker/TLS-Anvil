/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.server.tls12.rfc7465;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.anvilcore.annotation.*;
import de.rub.nds.anvilcore.teststate.AnvilTestCase;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.constants.AssertMsgs;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.derivationParameter.CipherSuiteDerivation;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.api.extension.ExtensionContext;

@ServerTest
public class RC4Ciphersuites extends Tls12Test {

    public ConditionEvaluationResult supportsRC4(ExtensionContext context) {
        List<CipherSuite> supported =
                new ArrayList<>(this.context.getFeatureExtractionResult().getCipherSuites());
        supported.removeIf(i -> !i.toString().contains("RC4"));

        return supported.size() == 0
                ? ConditionEvaluationResult.disabled("No RC4 Ciphersuite supported")
                : ConditionEvaluationResult.enabled("");
    }

    public boolean isRC4(CipherSuite cipherSuite) {
        return cipherSuite.toString().contains("RC4");
    }

    public boolean isNonRC4(CipherSuite cipherSuite) {
        return !isRC4(cipherSuite);
    }

    @AnvilTest(id = "7465-Wgqu8SjgSW")
    @ManualConfig(identifiers = "CIPHER_SUITE")
    @MethodCondition(method = "supportsRC4")
    @DynamicValueConstraints(affectedIdentifiers = "CIPHER_SUITE", methods = "isNonRC4")
    public void offerRC4AndOtherCiphers(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);
        CipherSuite selectedCipherSuite =
                parameterCombination.getParameter(CipherSuiteDerivation.class).getSelectedValue();

        List<CipherSuite> implemented =
                new ArrayList<>(
                        TestContext.getInstance().getFeatureExtractionResult().getCipherSuites());
        implemented.removeIf(i -> !i.toString().contains("RC4"));
        c.setDefaultClientSupportedCipherSuites(implemented);
        c.getDefaultClientSupportedCipherSuites().add(selectedCipherSuite);

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                new SendAction(new ClientHelloMessage(c)),
                new ReceiveTillAction(new ServerHelloDoneMessage()));

        State state = runner.execute(workflowTrace, c);

        WorkflowTrace trace = state.getWorkflowTrace();
        Validator.executedAsPlanned(state, testCase);

        ServerHelloMessage msg = trace.getFirstReceivedMessage(ServerHelloMessage.class);
        assertArrayEquals(
                selectedCipherSuite.getByteValue(),
                msg.getSelectedCipherSuite().getValue(),
                AssertMsgs.UNEXPECTED_CIPHER_SUITE);
    }

    @AnvilTest(id = "7465-YNsMZJY6pa")
    @DynamicValueConstraints(affectedIdentifiers = "CIPHER_SUITE", methods = "isRC4")
    public void onlyRC4Suites(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                new SendAction(new ClientHelloMessage(c)), new ReceiveAction(new AlertMessage()));

        State state = runner.execute(workflowTrace, c);
        Validator.receivedFatalAlert(state, testCase);
        ;
    }
}
