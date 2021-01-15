package de.rub.nds.tlstest.suite.tests.server.tls12.statemachine;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HeartbeatMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ActivateEncryptionAction;
import de.rub.nds.tlsattacker.core.workflow.action.DeactivateEncryptionAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.ServerTest;
import de.rub.nds.tlstest.framework.annotations.TestDescription;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.annotations.categories.Alert;
import de.rub.nds.tlstest.framework.annotations.categories.Compliance;
import de.rub.nds.tlstest.framework.annotations.categories.Crypto;
import de.rub.nds.tlstest.framework.annotations.categories.DeprecatedFeature;
import de.rub.nds.tlstest.framework.annotations.categories.Handshake;
import de.rub.nds.tlstest.framework.annotations.categories.Interoperability;
import de.rub.nds.tlstest.framework.annotations.categories.MessageStructure;
import de.rub.nds.tlstest.framework.annotations.categories.RecordLayer;
import de.rub.nds.tlstest.framework.annotations.categories.Security;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import de.rub.nds.tlstest.suite.tests.server.both.statemachine.SharedStateMachineTest;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

/**
 * Contains tests for known state machine (bugs) presented in "Protocol State
 * Fuzzing of TLS Implementations" (de Ruiter et al.)
 *
 * The tests cover paths which lead to security bugs as well as some paths where
 * specific messages resulted in a different error handling than others.
 */
@Tag("stateMachine")
@ServerTest
public class StateMachine extends Tls12Test {

    //Figure 2: path 0, 1, 10
    @TlsTest(description = "Send a Heartbeat Request after sending the Client Hello Message and observe the response")
    @Handshake(SeverityLevel.MEDIUM)
    @Compliance(SeverityLevel.HIGH)
    public void sendHeartbeatRequestAfterClientHello(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace workflowTrace = runner.generateWorkflowTraceUntilSendingMessage(WorkflowTraceType.HANDSHAKE, HandshakeMessageType.CLIENT_KEY_EXCHANGE);
        genericHeartbeatStateTest(runner, workflowTrace, config);
    }

    //Figure 2: path 0, 1, 10
    @TlsTest(description = "Send a Heartbeat Request after sending the Client Key Exchange Message and observer the response")
    @Handshake(SeverityLevel.MEDIUM)
    @Compliance(SeverityLevel.HIGH)
    public void sendHeartbeatRequestAfterClientKeyExchange(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace workflowTrace = runner.generateWorkflowTraceUntilSendingMessage(WorkflowTraceType.HANDSHAKE, ProtocolMessageType.CHANGE_CIPHER_SPEC);
        genericHeartbeatStateTest(runner, workflowTrace, config);
    }

    //Figure 2: path 0, 1, 10 and Figure 4: path 0, 1, 3, 5, 8
    @TlsTest(description = "Send a Heartbeat Request after sending the Change Cipher Spec Message and observer the response")
    @Handshake(SeverityLevel.MEDIUM)
    @Compliance(SeverityLevel.HIGH)
    public void sendHeartbeatRequestAfterChangeCipherSpec(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace workflowTrace = runner.generateWorkflowTraceUntilSendingMessage(WorkflowTraceType.HANDSHAKE, HandshakeMessageType.FINISHED);
        genericHeartbeatStateTest(runner, workflowTrace, config);
    }

    //Figure 2: 0, 1, 3, 5 and Figure 4: path 0, 1, 3, 4 
    @TlsTest(description = "Send a Client Hello Message after sending a Client Key Exchange Message")
    @Handshake(SeverityLevel.MEDIUM)
    @Compliance(SeverityLevel.HIGH)
    @Security(SeverityLevel.MEDIUM)
    public void secondClientHelloAfterClientKeyExchange(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace workflowTrace = runner.generateWorkflowTraceUntilSendingMessage(WorkflowTraceType.HANDSHAKE, ProtocolMessageType.CHANGE_CIPHER_SPEC);
        SendAction sendActionclientSecondMessageBatch = (SendAction) workflowTrace.getTlsActions().get(workflowTrace.getTlsActions().size() - 1);
        sendActionclientSecondMessageBatch.getMessages().add(new ClientHelloMessage(config));
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));
        runner.execute(workflowTrace, config).validateFinal(Validator::receivedFatalAlert);
    }

    //Figure 3: path 0, 1, 3, 5, 6, 2
    @TlsTest(description = "Send a Finished Message after the ServerHello")
    @Handshake(SeverityLevel.MEDIUM)
    @Compliance(SeverityLevel.HIGH)
    @Security(SeverityLevel.CRITICAL)
    public void sendFinishedAfterServerHello(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsAction(new SendAction(new FinishedMessage(config)));
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));
        runner.execute(workflowTrace, config).validateFinal(Validator::receivedFatalAlert);
    }

    //Figure 4: path 0, 2
    @Test
    @TestDescription("Begin the Handshake with a Finished Message")
    @Handshake(SeverityLevel.MEDIUM)
    @Compliance(SeverityLevel.HIGH)
    @Security(SeverityLevel.CRITICAL)
    public void beginWithFinished(WorkflowRunner runner) {
        Config config = getConfig();
        SharedStateMachineTest.sharedBeginWithFinishedTest(config, runner);
    }

    //Figure 4: path 0, 1, 3, 2
    @TlsTest(description = "Send two Client Key Exchange Messages")
    @Handshake(SeverityLevel.MEDIUM)
    @Compliance(SeverityLevel.HIGH)
    @Security(SeverityLevel.HIGH)
    public void secondClientKeyExchange(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace workflowTrace = runner.generateWorkflowTraceUntilSendingMessage(WorkflowTraceType.HANDSHAKE, ProtocolMessageType.CHANGE_CIPHER_SPEC);
        WorkflowConfigurationFactory workflowFactory = new WorkflowConfigurationFactory(config);

        SendAction sendActionclientSecondMessageBatch = (SendAction) workflowTrace.getTlsActions().get(workflowTrace.getTlsActions().size() - 1);
        workflowFactory.addClientKeyExchangeMessage(sendActionclientSecondMessageBatch.getMessages());
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));
        runner.execute(workflowTrace, config).validateFinal(Validator::receivedFatalAlert);
    }

    //Figure 4: path 0, 1, 3, 2
    @TlsTest(description = "Send two Client Key Exchange Messages with different Send Actions")
    @Handshake(SeverityLevel.MEDIUM)
    @Compliance(SeverityLevel.HIGH)
    @Security(SeverityLevel.HIGH)
    public void secondClientKeyExchangeDifferentAction(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace workflowTrace = runner.generateWorkflowTraceUntilSendingMessage(WorkflowTraceType.HANDSHAKE, ProtocolMessageType.CHANGE_CIPHER_SPEC);
        WorkflowConfigurationFactory workflowFactory = new WorkflowConfigurationFactory(config);

        SendAction sendActionSecondClientKeyExchange = new SendAction();
        workflowFactory.addClientKeyExchangeMessage(sendActionSecondClientKeyExchange.getMessages());
        workflowTrace.addTlsAction(sendActionSecondClientKeyExchange);
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));
        runner.execute(workflowTrace, config).validateFinal(Validator::receivedFatalAlert);
    }

    //Figure 4: path 0, 1, 3, 5, 2
    @TlsTest(description = "Send a second Client Key Exchange Message after sending Change Cipher Spec")
    @Handshake(SeverityLevel.MEDIUM)
    @Compliance(SeverityLevel.HIGH)
    @Security(SeverityLevel.MEDIUM)
    public void secondClientKeyExchangeAfterChangeCipherSpec(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace workflowTrace = runner.generateWorkflowTraceUntilSendingMessage(WorkflowTraceType.HANDSHAKE, HandshakeMessageType.FINISHED);
        WorkflowConfigurationFactory workflowFactory = new WorkflowConfigurationFactory(config);

        SendAction sendActionclientSecondMessageBatch = (SendAction) workflowTrace.getTlsActions().get(workflowTrace.getTlsActions().size() - 1);
        workflowFactory.addClientKeyExchangeMessage(sendActionclientSecondMessageBatch.getMessages());
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));
        runner.execute(workflowTrace, config).validateFinal(Validator::receivedFatalAlert);
    }

    //Figure 4: path 0, 1, 3, 5, 2
    @TlsTest(description = "Send a second unencrypted Client Key Exchange Message after sending Change Cipher Spec")
    @Handshake(SeverityLevel.MEDIUM)
    @Compliance(SeverityLevel.HIGH)
    @Security(SeverityLevel.MEDIUM)
    public void secondClientKeyExchangeAfterChangeCipherSpecUnencrypted(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace workflowTrace = runner.generateWorkflowTraceUntilSendingMessage(WorkflowTraceType.HANDSHAKE, HandshakeMessageType.FINISHED);
        WorkflowConfigurationFactory workflowFactory = new WorkflowConfigurationFactory(config);

        workflowTrace.addTlsAction(new DeactivateEncryptionAction());
        SendAction sendActionSecondKeyExchange = new SendAction();
        workflowFactory.addClientKeyExchangeMessage(sendActionSecondKeyExchange.getMessages());
        workflowTrace.addTlsAction(sendActionSecondKeyExchange);
        workflowTrace.addTlsAction(new ActivateEncryptionAction(false));
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));
        runner.execute(workflowTrace, config).validateFinal(Validator::receivedFatalAlert);
    }

    //Figure 7: path 0,2
    @Test
    @TestDescription("Begin the Handshake with Change Cipher Spec")
    @Handshake(SeverityLevel.MEDIUM)
    @Compliance(SeverityLevel.HIGH)
    @Security(SeverityLevel.HIGH)
    public void beginWithChangeCipherSpec(WorkflowRunner runner) {
        Config config = getConfig();
        SharedStateMachineTest.sharedBeginWithChangeCipherSpecTest(config, runner);
    }

    //Figure 7: path 0,3
    @TlsTest(description = "Begin the Handshake with Application Data")
    @Disabled
    @Handshake(SeverityLevel.MEDIUM)
    @Compliance(SeverityLevel.HIGH)
    @Security(SeverityLevel.CRITICAL)
    public void beginWithEmptyApplicationData(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        config.setDefaultApplicationMessageData("Test");
        WorkflowTrace workflowTrace = new WorkflowTrace();
        Record record = new Record();
        record.setCompleteRecordBytes(Modifiable.explicit(new byte[0]));
        ApplicationMessage emptyApplicationMessage = new ApplicationMessage(config);
        //emptyApplicationMessage.setDataConfig(new byte[0]);
        SendAction sendActionApplicationData = new SendAction(emptyApplicationMessage);
        sendActionApplicationData.setRecords(record);

        workflowTrace.addTlsAction(sendActionApplicationData);
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));
        runner.execute(workflowTrace, config).validateFinal(Validator::receivedFatalAlert);
    }

    //Figure 7: path 0,3 (with content in Application Message)
    @Test
    @TestDescription("Begin the Handshake with Application Data")
    @Handshake(SeverityLevel.MEDIUM)
    @Compliance(SeverityLevel.HIGH)
    @Security(SeverityLevel.CRITICAL)
    public void beginWithApplicationData(WorkflowRunner runner) {
        Config config = getConfig();
        SharedStateMachineTest.sharedBeginWithApplicationDataTest(config, runner);
    }

    //Figure 7: 0, 1, 5, 6, 7, 8
    @TlsTest(description = "Send a second Change Cipher Spec after receiving the servers Finished Message")
    @Handshake(SeverityLevel.MEDIUM)
    @Compliance(SeverityLevel.HIGH)
    @Security(SeverityLevel.HIGH)
    public void secondChangeCipherSpecAfterHandshake(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        workflowTrace.addTlsAction(new SendAction(new ChangeCipherSpecMessage()));
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));
        runner.execute(workflowTrace, config).validateFinal(Validator::receivedFatalAlert);
    }

    //Figure 7: 0, 1, 5, 6, 7, 8
    @TlsTest(description = "Send a second Change Cipher Spec after receiving the servers Finished Message")
    @Handshake(SeverityLevel.MEDIUM)
    @Compliance(SeverityLevel.HIGH)
    @Security(SeverityLevel.HIGH)
    public void secondChangeCipherSpecAfterHandshakeUnencrypted(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        workflowTrace.addTlsAction(new DeactivateEncryptionAction());
        workflowTrace.addTlsAction(new SendAction(new ChangeCipherSpecMessage()));
        workflowTrace.addTlsAction(new ActivateEncryptionAction(false));
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));
        runner.execute(workflowTrace, config).validateFinal(Validator::receivedFatalAlert);
    }

    //Figure 7: path 0, 1, 4
    @TlsTest(description = "Send a second Client Hello after receiving the first batch of server messages")
    @Handshake(SeverityLevel.MEDIUM)
    @Compliance(SeverityLevel.HIGH)
    @Security(SeverityLevel.HIGH)
    public void secondClientHelloAfterServerHello(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        SharedStateMachineTest.sharedSecondClientHelloAfterServerHelloTest(config, runner);
    }

    //Figure 7: path 0, 1, 4
    @TlsTest(description = "Send two Client Hello Messages at the beginning of the Handshake")
    @Handshake(SeverityLevel.MEDIUM)
    @Compliance(SeverityLevel.HIGH)
    @Security(SeverityLevel.HIGH)
    public void secondClientHello(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        SharedStateMachineTest.sharedSecondClientHelloTest(config, runner);
    }

    //Figure 8: path 0, 1, 6
    @TlsTest(description = "Send a Change Cipher Spec before the Client Key Exchange Message")
    @Handshake(SeverityLevel.MEDIUM)
    @Compliance(SeverityLevel.HIGH)
    @Security(SeverityLevel.CRITICAL)
    public void earlyChangeCipherSpec(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace workflowTrace = runner.generateWorkflowTraceUntilSendingMessage(WorkflowTraceType.HANDSHAKE, ProtocolMessageType.CHANGE_CIPHER_SPEC);
        SendAction sendActionclientSecondMessageBatch = (SendAction) workflowTrace.getTlsActions().get(workflowTrace.getTlsActions().size() - 1);
        sendActionclientSecondMessageBatch.getMessages().add(0, new ChangeCipherSpecMessage());
        sendActionclientSecondMessageBatch.getMessages().add(new FinishedMessage(config));

        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));
        runner.execute(workflowTrace, config).validateFinal(Validator::receivedFatalAlert);
    }

    private void genericHeartbeatStateTest(WorkflowRunner runner, WorkflowTrace workflowTrace, Config config) {
        workflowTrace.addTlsAction(new SendAction(new HeartbeatMessage()));
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));
        runner.execute(workflowTrace, config).validateFinal(state -> {
            WorkflowTrace executedTrace = state.getWorkflowTrace();
            if (WorkflowTraceUtil.didReceiveMessage(ProtocolMessageType.HEARTBEAT, executedTrace)) {
                return;
            } else {
                Validator.receivedFatalAlert(state);
            }
        });
    }
}
