/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.client.tls12.statemachine;

import de.rub.nds.anvilcore.annotation.*;
import de.rub.nds.anvilcore.coffee4j.model.ModelFromScope;
import de.rub.nds.anvilcore.teststate.AnvilTestCase;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceConfigurationUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ActivateEncryptionAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import de.rub.nds.tlstest.suite.tests.client.both.statemachine.SharedStateMachineTest;
import org.junit.jupiter.api.Tag;

/**
 * Contains tests to evaluate the target's state machine. Some test flows are based on results found
 * for TLS 1.2 servers in "Protocol State Fuzzing of TLS Implementations" (de Ruiter et al.)
 */
@Tag("statemachine")
@ClientTest
public class StateMachine extends Tls12Test {

    public boolean isNotAnonCipherSuite(CipherSuite cipherSuite) {
        return !cipherSuite.isAnon();
    }

    @AnvilTest(id = "XSM-g5sZueNdGS")
    @DynamicValueConstraints(affectedIdentifiers = "CIPHER_SUITE", methods = "isNotAnonCipherSuite")
    @ModelFromScope(modelType = "CERTIFICATE")
    @ExcludeParameter("CERTIFICATE")
    public void omitCertificate(AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        SendAction sendActionServerHelloBatch =
                (SendAction)
                        WorkflowTraceConfigurationUtil.getFirstStaticConfiguredSendAction(
                                workflowTrace, HandshakeMessageType.CERTIFICATE);
        sendActionServerHelloBatch.getConfiguredMessages().remove(1);

        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));

        State state = runner.execute(workflowTrace, config);
        Validator.receivedFatalAlert(state, testCase);
    }

    @AnvilTest(id = "XSM-YWHyrAVFo3")
    @ModelFromScope(modelType = "CERTIFICATE")
    public void omitChangeCipherSpecEncryptedFinished(
            AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);

        WorkflowTrace workflowTrace =
                runner.generateWorkflowTraceUntilSendingMessage(
                        WorkflowTraceType.HANDSHAKE, ProtocolMessageType.CHANGE_CIPHER_SPEC);
        workflowTrace.addTlsAction(new ActivateEncryptionAction());
        // RC4 requires a continuous state - ActivateEncryption will create
        // a new Decryptor - this has to be reverted
        workflowTrace.addTlsAction(new SendAction(new FinishedMessage()));
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));

        State state = runner.execute(workflowTrace, config);
        Validator.receivedFatalAlert(state, testCase);
    }

    @AnvilTest(id = "XSM-TPgoAceVQB")
    public void sendServerHelloTwice(AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);
        SharedStateMachineTest.sharedSendServerHelloTwiceTest(config, runner, testCase);
    }

    @AnvilTest(id = "XSM-jnFHuGoQR3")
    @ModelFromScope(modelType = "CERTIFICATE")
    public void sendSecondServerHelloAfterClientFinished(
            AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);
        WorkflowTrace workflowTrace =
                runner.generateWorkflowTraceUntilSendingMessage(
                        WorkflowTraceType.HANDSHAKE, ProtocolMessageType.CHANGE_CIPHER_SPEC);
        ServerHelloMessage secondServerHello = new ServerHelloMessage(config);
        secondServerHello.setIncludeInDigest(Modifiable.explicit(false));
        secondServerHello.setAdjustContext(Modifiable.explicit(false));
        workflowTrace.addTlsAction(new SendAction(secondServerHello));
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));

        // There is no renegotiation in TLS 1.3 and TLS 1.2 requires a completed handshake
        State state = runner.execute(workflowTrace, config);
        Validator.receivedFatalAlert(state, testCase);
    }

    @AnvilTest(id = "XSM-SJ9mzNY9kZ")
    public void sendResumptionMessageFlow(AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);
        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsAction(new ReceiveAction(new ClientHelloMessage()));
        workflowTrace.addTlsAction(
                new SendAction(new ServerHelloMessage(config), new ChangeCipherSpecMessage()));
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));

        State state = runner.execute(workflowTrace, config);
        Validator.receivedFatalAlert(state, testCase);
    }

    @NonCombinatorialAnvilTest(id = "XSM-Rdcvemgd4h")
    public void beginWithFinished(WorkflowRunner runner, AnvilTestCase testCase) {
        Config config = getConfig();
        SharedStateMachineTest.sharedBeginWithFinishedTest(config, runner, testCase);
    }

    @NonCombinatorialAnvilTest(id = "XSM-Bv4mqPoKa4")
    public void beginWithApplicationData(WorkflowRunner runner, AnvilTestCase testCase) {
        Config config = getConfig();
        SharedStateMachineTest.sharedBeginWithApplicationDataTest(config, runner, testCase);
    }
}
