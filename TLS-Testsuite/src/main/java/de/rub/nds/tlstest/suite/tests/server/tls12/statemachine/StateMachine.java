package de.rub.nds.tlstest.suite.tests.server.tls12.statemachine;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
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
import de.rub.nds.tlsattacker.core.workflow.action.ResetRecordCipherListsAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.MethodCondition;
import de.rub.nds.tlstest.framework.annotations.ServerTest;
import de.rub.nds.tlstest.framework.annotations.TestDescription;
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
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import de.rub.nds.tlstest.suite.tests.server.both.statemachine.SharedStateMachineTest;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;
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
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    @AlertCategory(SeverityLevel.LOW)
    public void sendHeartbeatRequestAfterClientHello(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace workflowTrace = runner.generateWorkflowTraceUntilSendingMessage(WorkflowTraceType.HANDSHAKE, HandshakeMessageType.CLIENT_KEY_EXCHANGE);
        genericHeartbeatStateTest(runner, workflowTrace, config);
    }

    //Figure 2: path 0, 1, 10
    @TlsTest(description = "Send a Heartbeat Request after sending the Client Key Exchange Message and observer the response")
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    @AlertCategory(SeverityLevel.LOW)
    public void sendHeartbeatRequestAfterClientKeyExchange(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace workflowTrace = runner.generateWorkflowTraceUntilSendingMessage(WorkflowTraceType.HANDSHAKE, ProtocolMessageType.CHANGE_CIPHER_SPEC);
        genericHeartbeatStateTest(runner, workflowTrace, config);
    }

    //Figure 2: path 0, 1, 10 and Figure 4: path 0, 1, 3, 5, 8
    @TlsTest(description = "Send a Heartbeat Request after sending the Change Cipher Spec Message and observer the response")
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    @AlertCategory(SeverityLevel.LOW)
    public void sendHeartbeatRequestAfterChangeCipherSpec(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace workflowTrace = runner.generateWorkflowTraceUntilSendingMessage(WorkflowTraceType.HANDSHAKE, HandshakeMessageType.FINISHED);
        genericHeartbeatStateTest(runner, workflowTrace, config);
    }

    //Figure 2: 0, 1, 3, 5 and Figure 4: path 0, 1, 3, 4 
    @TlsTest(description = "Send a Client Hello Message after sending a Client Key Exchange Message")
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    @SecurityCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.LOW)
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
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    @SecurityCategory(SeverityLevel.CRITICAL)
    @AlertCategory(SeverityLevel.LOW)
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
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    @SecurityCategory(SeverityLevel.CRITICAL)
    @AlertCategory(SeverityLevel.LOW)
    public void beginWithFinished(WorkflowRunner runner) {
        Config config = getConfig();
        SharedStateMachineTest.sharedBeginWithFinishedTest(config, runner);
    }

    //Figure 4: path 0, 1, 3, 2
    @TlsTest(description = "Send two Client Key Exchange Messages")
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    @SecurityCategory(SeverityLevel.HIGH)
    @AlertCategory(SeverityLevel.LOW)
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
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    @SecurityCategory(SeverityLevel.HIGH)
    @AlertCategory(SeverityLevel.LOW)
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
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    @SecurityCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.LOW)
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
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    @SecurityCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.LOW)
    public void secondClientKeyExchangeAfterChangeCipherSpecUnencrypted(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace workflowTrace = runner.generateWorkflowTraceUntilSendingMessage(WorkflowTraceType.HANDSHAKE, HandshakeMessageType.FINISHED);
        WorkflowConfigurationFactory workflowFactory = new WorkflowConfigurationFactory(config);

        workflowTrace.addTlsAction(new DeactivateEncryptionAction());
        SendAction sendActionSecondKeyExchange = new SendAction();
        workflowFactory.addClientKeyExchangeMessage(sendActionSecondKeyExchange.getMessages());
        workflowTrace.addTlsAction(sendActionSecondKeyExchange);
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));
        runner.execute(workflowTrace, config).validateFinal(Validator::receivedFatalAlert);
    }

    public ConditionEvaluationResult onlySupportsTls12() {
        if(TestContext.getInstance().getSiteReport().getResult(AnalyzedProperty.SUPPORTS_TLS_1_3) == TestResult.FALSE) {
            return ConditionEvaluationResult.enabled("Server does not support TLS 1.3");
        }
        return ConditionEvaluationResult.disabled("Server supports TLS 1.3, where a CCS at the beginning of the handshake is permitted by RFC 8446 4.2.2");
    }
    
    
    //Figure 7: path 0,2
    @Test
    @TestDescription("Begin the Handshake with Change Cipher Spec. A stateless server may ignore this record from TLS 1.3 on.")
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    @SecurityCategory(SeverityLevel.HIGH)
    @AlertCategory(SeverityLevel.LOW)
    @MethodCondition(method="onlySupportsTls12")
    public void beginWithChangeCipherSpec(WorkflowRunner runner) {
        Config config = getConfig();
        SharedStateMachineTest.sharedBeginWithChangeCipherSpecTest(config, runner);
    }

    //Figure 7: path 0,3
    @Test
    @TestDescription("Begin the Handshake with empty Application Data")
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    @SecurityCategory(SeverityLevel.CRITICAL)
    @AlertCategory(SeverityLevel.LOW)
    public void beginWithEmptyApplicationData(WorkflowRunner runner) {
        Config config = getConfig();
        runner.setPreparedConfig(config);
        WorkflowTrace workflowTrace = new WorkflowTrace();
        Record record = new Record();
        record.setProtocolMessageBytes(Modifiable.explicit(new byte[0]));
        ApplicationMessage emptyApplicationMessage = new ApplicationMessage(config);
        SendAction sendActionApplicationData = new SendAction(emptyApplicationMessage);
        sendActionApplicationData.setRecords(record);

        workflowTrace.addTlsAction(sendActionApplicationData);
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));
        runner.execute(workflowTrace, config).validateFinal(Validator::receivedFatalAlert);
    }

    //Figure 7: path 0,3 (with content in Application Message)
    @Test
    @TestDescription("Begin the Handshake with Application Data")
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    @SecurityCategory(SeverityLevel.CRITICAL)
    @AlertCategory(SeverityLevel.LOW)
    public void beginWithApplicationData(WorkflowRunner runner) {
        Config config = getConfig();
        SharedStateMachineTest.sharedBeginWithApplicationDataTest(config, runner);
    }

    //Figure 7: 0, 1, 5, 6, 7, 8
    @TlsTest(description = "Send a second Change Cipher Spec after receiving the servers Finished Message")
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    @SecurityCategory(SeverityLevel.HIGH)
    @AlertCategory(SeverityLevel.LOW)
    @Tag("libressl")
    public void secondChangeCipherSpecAfterHandshake(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        ChangeCipherSpecMessage secondChangeCipherSpec = new ChangeCipherSpecMessage();
        secondChangeCipherSpec.setAdjustContext(Modifiable.explicit(false));
        workflowTrace.addTlsAction(new SendAction(secondChangeCipherSpec));
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));
        runner.execute(workflowTrace, config).validateFinal(Validator::receivedFatalAlert);
    }

    //Figure 7: 0, 1, 5, 6, 7, 8
    @TlsTest(description = "Send a second Change Cipher Spec after receiving the servers Finished Message")
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    @SecurityCategory(SeverityLevel.HIGH)
    @AlertCategory(SeverityLevel.LOW)
    public void secondChangeCipherSpecAfterHandshakeUnencrypted(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        workflowTrace.addTlsAction(new DeactivateEncryptionAction());
        ChangeCipherSpecMessage secondChangeCipherSpec = new ChangeCipherSpecMessage();
        secondChangeCipherSpec.setAdjustContext(Modifiable.explicit(false));
        workflowTrace.addTlsAction(new SendAction(secondChangeCipherSpec));
        //for stream ciphers, the state must be restored as a decryption already took place in this test
        workflowTrace.addTlsAction(new ResetRecordCipherListsAction(2, 2));
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));
        runner.execute(workflowTrace, config).validateFinal(Validator::receivedFatalAlert);
    }

    //Figure 7: path 0, 1, 4
    @TlsTest(description = "Send a second Client Hello after receiving the first batch of server messages")
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    @SecurityCategory(SeverityLevel.HIGH)
    @AlertCategory(SeverityLevel.LOW)
    public void secondClientHelloAfterServerHello(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        SharedStateMachineTest.sharedSecondClientHelloAfterServerHelloTest(config, runner);
    }

    //Figure 7: path 0, 1, 4
    @TlsTest(description = "Send two Client Hello Messages at the beginning of the Handshake")
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    @SecurityCategory(SeverityLevel.HIGH)
    @AlertCategory(SeverityLevel.LOW)
    public void secondClientHello(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        SharedStateMachineTest.sharedSecondClientHelloTest(config, runner);
    }

    //Figure 8: path 0, 1, 6
    @TlsTest(description = "Send a Change Cipher Spec before the Client Key Exchange Message")
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    @SecurityCategory(SeverityLevel.CRITICAL)
    @AlertCategory(SeverityLevel.LOW)
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
