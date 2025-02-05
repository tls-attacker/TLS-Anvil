/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.server.tls12.statemachine;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.MethodCondition;
import de.rub.nds.anvilcore.annotation.NonCombinatorialAnvilTest;
import de.rub.nds.anvilcore.annotation.ServerTest;
import de.rub.nds.anvilcore.teststate.AnvilTestCase;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceResultUtil;
import de.rub.nds.tlsattacker.core.workflow.action.DeactivateEncryptionAction;
import de.rub.nds.tlsattacker.core.workflow.action.GenericReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import de.rub.nds.tlstest.suite.tests.server.both.statemachine.SharedStateMachineTest;
import java.util.List;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;

/**
 * Contains tests for known state machine (bugs) presented in "Protocol State Fuzzing of TLS
 * Implementations" (de Ruiter et al.)
 *
 * <p>The tests cover paths which lead to security bugs as well as some paths where specific
 * messages resulted in a different error handling than others.
 */
@Tag("stateMachine")
@ServerTest
public class StateMachine extends Tls12Test {

    // Figure 2: path 0, 1, 10
    @AnvilTest(id = "XSM-N5VTen5U6e")
    public void sendHeartbeatRequestAfterClientHello(
            AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);
        WorkflowTrace workflowTrace =
                runner.generateWorkflowTraceUntilSendingMessage(
                        WorkflowTraceType.HANDSHAKE, HandshakeMessageType.CLIENT_KEY_EXCHANGE);
        genericHeartbeatStateTest(runner, workflowTrace, config, testCase);
    }

    // Figure 2: path 0, 1, 10
    @AnvilTest(id = "XSM-hUmvB1guzB")
    public void sendHeartbeatRequestAfterClientKeyExchange(
            AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);
        WorkflowTrace workflowTrace =
                runner.generateWorkflowTraceUntilSendingMessage(
                        WorkflowTraceType.HANDSHAKE, ProtocolMessageType.CHANGE_CIPHER_SPEC);
        genericHeartbeatStateTest(runner, workflowTrace, config, testCase);
    }

    // Figure 2: path 0, 1, 10 and Figure 4: path 0, 1, 3, 5, 8
    @AnvilTest(id = "XSM-RGwxgMCeT9")
    public void sendHeartbeatRequestAfterChangeCipherSpec(
            AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);
        WorkflowTrace workflowTrace =
                runner.generateWorkflowTraceUntilSendingMessage(
                        WorkflowTraceType.HANDSHAKE, HandshakeMessageType.FINISHED);
        genericHeartbeatStateTest(runner, workflowTrace, config, testCase);
    }

    // Figure 2: 0, 1, 3, 5 and Figure 4: path 0, 1, 3, 4
    @AnvilTest(id = "XSM-JoVdmVr5by")
    public void secondClientHelloAfterClientKeyExchange(
            AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);
        WorkflowTrace workflowTrace =
                runner.generateWorkflowTraceUntilSendingMessage(
                        WorkflowTraceType.HANDSHAKE, ProtocolMessageType.CHANGE_CIPHER_SPEC);
        SendAction sendActionclientSecondMessageBatch =
                (SendAction)
                        workflowTrace.getTlsActions().get(workflowTrace.getTlsActions().size() - 1);
        sendActionclientSecondMessageBatch
                .getConfiguredMessages()
                .add(new ClientHelloMessage(config));
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));
        State state = runner.execute(workflowTrace, config);
        Validator.receivedFatalAlert(state, testCase);
        ;
    }

    // Figure 3: path 0, 1, 3, 5, 6, 2
    @AnvilTest(id = "XSM-uscvmqxrG3")
    public void sendFinishedAfterServerHello(AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsAction(new SendAction(new FinishedMessage()));
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));
        State state = runner.execute(workflowTrace, config);
        Validator.receivedFatalAlert(state, testCase);
        ;
    }

    // Figure 4: path 0, 2
    @NonCombinatorialAnvilTest(id = "XSM-hV8iCuJCXT")
    public void beginWithFinished(WorkflowRunner runner, AnvilTestCase testCase) {
        Config config = getConfig();
        SharedStateMachineTest.sharedBeginWithFinishedTest(config, runner, testCase);
    }

    // Figure 4: path 0, 1, 3, 2
    @AnvilTest(id = "XSM-zmpmr7nVki")
    public void secondClientKeyExchange(AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);
        WorkflowTrace workflowTrace =
                runner.generateWorkflowTraceUntilSendingMessage(
                        WorkflowTraceType.HANDSHAKE, ProtocolMessageType.CHANGE_CIPHER_SPEC);
        WorkflowConfigurationFactory workflowFactory = new WorkflowConfigurationFactory(config);

        SendAction sendActionclientSecondMessageBatch =
                (SendAction)
                        workflowTrace.getTlsActions().get(workflowTrace.getTlsActions().size() - 1);
        workflowFactory.addClientKeyExchangeMessage(
                sendActionclientSecondMessageBatch.getConfiguredMessages());
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));
        State state = runner.execute(workflowTrace, config);
        Validator.receivedFatalAlert(state, testCase);
        ;
    }

    // Figure 4: path 0, 1, 3, 2
    @AnvilTest(id = "XSM-7HDSP4DS95")
    public void secondClientKeyExchangeDifferentAction(
            AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);
        WorkflowTrace workflowTrace =
                runner.generateWorkflowTraceUntilSendingMessage(
                        WorkflowTraceType.HANDSHAKE, ProtocolMessageType.CHANGE_CIPHER_SPEC);
        WorkflowConfigurationFactory workflowFactory = new WorkflowConfigurationFactory(config);

        SendAction sendActionSecondClientKeyExchange = new SendAction();
        workflowFactory.addClientKeyExchangeMessage(
                sendActionSecondClientKeyExchange.getConfiguredMessages());
        workflowTrace.addTlsAction(sendActionSecondClientKeyExchange);
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));
        State state = runner.execute(workflowTrace, config);
        Validator.receivedFatalAlert(state, testCase);
        ;
    }

    // Figure 4: path 0, 1, 3, 5, 2
    @AnvilTest(id = "XSM-RPJWoZQFc5")
    public void secondClientKeyExchangeAfterChangeCipherSpec(
            AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);
        WorkflowTrace workflowTrace =
                runner.generateWorkflowTraceUntilSendingMessage(
                        WorkflowTraceType.HANDSHAKE, HandshakeMessageType.FINISHED);
        WorkflowConfigurationFactory workflowFactory = new WorkflowConfigurationFactory(config);

        SendAction sendActionclientSecondMessageBatch =
                (SendAction)
                        workflowTrace.getTlsActions().get(workflowTrace.getTlsActions().size() - 1);
        workflowFactory.addClientKeyExchangeMessage(
                sendActionclientSecondMessageBatch.getConfiguredMessages());
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));
        State state = runner.execute(workflowTrace, config);
        Validator.receivedFatalAlert(state, testCase);
    }

    // Figure 4: path 0, 1, 3, 5, 2
    @AnvilTest(id = "XSM-9TgGnWGw1S")
    public void secondClientKeyExchangeAfterChangeCipherSpecUnencrypted(
            AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);
        WorkflowTrace workflowTrace =
                runner.generateWorkflowTraceUntilSendingMessage(
                        WorkflowTraceType.HANDSHAKE, HandshakeMessageType.FINISHED);
        WorkflowConfigurationFactory workflowFactory = new WorkflowConfigurationFactory(config);

        workflowTrace.addTlsAction(new DeactivateEncryptionAction());
        SendAction sendActionSecondKeyExchange = new SendAction();
        workflowFactory.addClientKeyExchangeMessage(
                sendActionSecondKeyExchange.getConfiguredMessages());
        workflowTrace.addTlsAction(sendActionSecondKeyExchange);
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));
        State state = runner.execute(workflowTrace, config);
        Validator.receivedFatalAlert(state, testCase);
    }

    public ConditionEvaluationResult onlySupportsTls12() {
        if (TestContext.getInstance()
                        .getFeatureExtractionResult()
                        .getResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_3)
                == TestResults.FALSE) {
            return ConditionEvaluationResult.enabled("Server does not support TLS 1.3");
        }
        return ConditionEvaluationResult.disabled(
                "Server supports TLS 1.3, where a CCS at the beginning of the handshake is permitted by RFC 8446 4.2.2");
    }

    // Figure 7: path 0,2
    @NonCombinatorialAnvilTest(id = "XSM-1yXVP5Gbsr")
    @MethodCondition(method = "onlySupportsTls12")
    public void beginWithChangeCipherSpec(WorkflowRunner runner, AnvilTestCase testCase) {
        Config config = getConfig();
        SharedStateMachineTest.sharedBeginWithChangeCipherSpecTest(config, runner, testCase);
    }

    // Figure 7: path 0,3
    @NonCombinatorialAnvilTest(id = "XSM-Lz5fCfdmQi")
    public void beginWithEmptyApplicationData(WorkflowRunner runner, AnvilTestCase testCase) {
        Config config = getConfig();
        runner.setPreparedConfig(config);
        WorkflowTrace workflowTrace = new WorkflowTrace();
        Record record = new Record();
        record.setProtocolMessageBytes(Modifiable.explicit(new byte[0]));
        ApplicationMessage emptyApplicationMessage = new ApplicationMessage();
        SendAction sendActionApplicationData = new SendAction(emptyApplicationMessage);
        sendActionApplicationData.setConfiguredRecords(List.of(record));

        workflowTrace.addTlsAction(sendActionApplicationData);
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));
        State state = runner.execute(workflowTrace, config);
        Validator.receivedFatalAlert(state, testCase);
        ;
    }

    // Figure 7: path 0,3 (with content in Application Message)
    @NonCombinatorialAnvilTest(id = "XSM-tVGt2rqQy1")
    public void beginWithApplicationData(WorkflowRunner runner, AnvilTestCase testCase) {
        Config config = getConfig();
        SharedStateMachineTest.sharedBeginWithApplicationDataTest(config, runner, testCase);
    }

    // Figure 7: 0, 1, 5, 6, 7, 8
    @AnvilTest(id = "XSM-jQ4aV9UCUM")
    @Tag("libressl")
    public void secondChangeCipherSpecAfterHandshake(
            AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        ChangeCipherSpecMessage secondChangeCipherSpec = new ChangeCipherSpecMessage();
        secondChangeCipherSpec.setAdjustContext(Modifiable.explicit(false));
        workflowTrace.addTlsAction(new SendAction(secondChangeCipherSpec));
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));
        State state = runner.execute(workflowTrace, config);
        Validator.receivedFatalAlert(state, testCase);
    }

    // Figure 7: 0, 1, 5, 6, 7, 8
    @AnvilTest(id = "XSM-WzfTB6GdUF")
    public void secondChangeCipherSpecAfterHandshakeUnencrypted(
            AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        workflowTrace.addTlsAction(new DeactivateEncryptionAction());
        ChangeCipherSpecMessage secondChangeCipherSpec = new ChangeCipherSpecMessage();
        secondChangeCipherSpec.setAdjustContext(Modifiable.explicit(false));
        workflowTrace.addTlsAction(new SendAction(secondChangeCipherSpec));
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));
        State state = runner.execute(workflowTrace, config);
        Validator.receivedFatalAlert(state, testCase);
    }

    // Figure 7: path 0, 1, 4
    @AnvilTest(id = "XSM-mnyxwyTTK2")
    public void secondClientHelloAfterServerHello(AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);
        SharedStateMachineTest.sharedSecondClientHelloAfterServerHelloTest(
                config, runner, testCase);
    }

    // Figure 7: path 0, 1, 4
    @AnvilTest(id = "XSM-xDPE4XDweY")
    public void secondClientHello(AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);
        SharedStateMachineTest.sharedSecondClientHelloTest(config, runner, testCase);
    }

    // Figure 8: path 0, 1, 6
    @AnvilTest(id = "XSM-dV8FPhVnww")
    public void earlyChangeCipherSpec(AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);
        WorkflowTrace workflowTrace =
                runner.generateWorkflowTraceUntilSendingMessage(
                        WorkflowTraceType.HANDSHAKE, ProtocolMessageType.CHANGE_CIPHER_SPEC);
        SendAction sendActionclientSecondMessageBatch =
                (SendAction)
                        workflowTrace.getTlsActions().get(workflowTrace.getTlsActions().size() - 1);
        sendActionclientSecondMessageBatch
                .getConfiguredMessages()
                .add(0, new ChangeCipherSpecMessage());
        sendActionclientSecondMessageBatch.getConfiguredMessages().add(new FinishedMessage());

        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));
        State state = runner.execute(workflowTrace, config);
        Validator.receivedFatalAlert(state, testCase);
        ;
    }

    private void genericHeartbeatStateTest(
            WorkflowRunner runner,
            WorkflowTrace workflowTrace,
            Config config,
            AnvilTestCase testCase) {
        workflowTrace.addTlsAction(new SendAction(new HeartbeatMessage()));
        workflowTrace.addTlsAction(new GenericReceiveAction());
        State state = runner.execute(workflowTrace, config);

        WorkflowTrace executedTrace = state.getWorkflowTrace();
        if (WorkflowTraceResultUtil.didReceiveMessage(
                executedTrace, ProtocolMessageType.HEARTBEAT)) {
            return;
        } else if (executedTrace.executedAsPlanned() && !Validator.socketClosed(state)) {
            testCase.addAdditionalResultInfo("SUT chose to silently discard Heartbeat Request");
        } else {
            Validator.receivedFatalAlert(state, testCase);
        }
    }
}
