package de.rub.nds.tlstest.suite.tests.server.tls13.statemachine;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.DHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.RSAClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.ScopeLimitations;
import de.rub.nds.tlstest.framework.annotations.ServerTest;
import de.rub.nds.tlstest.framework.annotations.TestDescription;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.annotations.categories.Security;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.DerivationType;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
import de.rub.nds.tlstest.suite.tests.server.both.statemachine.SharedStateMachineTest;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

/**
 * Contains tests to evaluate the target's state machine. Some test flows are based
 * on results found for TLS 1.2 servers in 
 * "Protocol State Fuzzing of TLS Implementations" (de Ruiter et al.)
 */
@Tag("statemachine")
@ServerTest
public class StateMachine extends Tls13Test {
    
    @TlsTest(description = "Send two Client Hello Messages at the beginning of the Handshake")
    @Security(SeverityLevel.CRITICAL)
    public void secondClientHello(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        SharedStateMachineTest.sharedSecondClientHelloTest(config, runner);
    }
    
    @TlsTest(description = "Send a second Client Hello after receiving the server's Handshake messages")
    @Security(SeverityLevel.CRITICAL)
    public void secondClientHelloAfterServerHelloMessages(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        SharedStateMachineTest.sharedSecondClientHelloAfterServerHelloTest(config, runner);
    }
    
    @Test
    @TestDescription("An implementation may receive an unencrypted record of type " +
            "change_cipher_spec consisting of the single byte value 0x01 at any " +
            "time after the first ClientHello message has been sent or received")   
    @Security(SeverityLevel.CRITICAL)
    public void beginWithChangeCipherSpec(WorkflowRunner runner) {
        Config config = getConfig();
        SharedStateMachineTest.sharedBeginWithChangeCipherSpecTest(config, runner);
    }
    
    @Test
    @TestDescription("Begin the Handshake with Application Data")   
    @Security(SeverityLevel.CRITICAL)
    public void beginWithApplicationData(WorkflowRunner runner) {
        Config config = getConfig();
        SharedStateMachineTest.sharedBeginWithApplicationDataTest(config, runner);
    }
    
    @Test
    @TestDescription("Begin the Handshake with a Finished Message")   
    @Security(SeverityLevel.CRITICAL)
    public void beginWithFinished(WorkflowRunner runner) {
        Config config = getConfig();
        SharedStateMachineTest.sharedBeginWithFinishedTest(config, runner);
    }

    
    @TlsTest(description = "If an implementation " +
        "detects a change_cipher_spec record received before the first " +
        "ClientHello message or after the peer's Finished message, it MUST be " +
        "treated as an unexpected record type (though stateless servers may " +
        "not be able to distinguish these cases from allowed cases).")
    @RFC(number = 8446, section = "5. Record Protocol")
    @Security(SeverityLevel.LOW)
    public void sendLegacyChangeCipherSpecAfterFinished(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        workflowTrace.addTlsAction(new SendAction(new ChangeCipherSpecMessage()));
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));
        
        runner.execute(workflowTrace, config).validateFinal(Validator::receivedFatalAlert);
    }
    
    @TlsTest(description = "An" +
        "implementation which receives any other change_cipher_spec value or " +
        "which receives a protected change_cipher_spec record MUST abort the " +
        "handshake with an \"unexpected_message\" alert.")
    @RFC(number = 8446, section = "5. Record Protocol")
    @Security(SeverityLevel.LOW)
    public void sendEncryptedChangeCipherSpec(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        
        SendAction sendActionCCS = new SendAction(new ChangeCipherSpecMessage());
        Record ccsRecord = new Record();
        ccsRecord.setAllowEncryptedChangeCipherSpec(true);
        sendActionCCS.setRecords(ccsRecord);
        
        workflowTrace.addTlsAction(sendActionCCS);
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));
        
        runner.execute(workflowTrace, config).validateFinal(Validator::receivedFatalAlert);
    }
    
    @TlsTest(description = "Send a legacy ECDH Client Key Exchange Message instead of just a Finished")
    @Security(SeverityLevel.LOW)
    public void sendECDHClientKeyExchange(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsAction(new SendAction(new ECDHClientKeyExchangeMessage(config)));
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));
        
        runner.execute(workflowTrace, config).validateFinal(Validator::receivedFatalAlert);
    }
    
    @TlsTest(description = "Send a legacy DH Client Key Exchange Message instead of just a Finished")
    @Security(SeverityLevel.LOW)
    public void sendDHClientKeyExchange(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsAction(new SendAction(new DHClientKeyExchangeMessage(config)));
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));
        
        runner.execute(workflowTrace, config).validateFinal(Validator::receivedFatalAlert);
    }
    
    @TlsTest(description = "Send a legacy RSA Client Key Exchange Message instead of just a Finished")
    @Security(SeverityLevel.LOW)
    public void sendRSAClientKeyExchange(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsAction(new SendAction(new RSAClientKeyExchangeMessage(config)));
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));
        
        runner.execute(workflowTrace, config).validateFinal(Validator::receivedFatalAlert);
    }
}
