package de.rub.nds.tlstest.suite.tests.client.tls12.statemachine;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ActivateEncryptionAction;
import de.rub.nds.tlsattacker.core.workflow.action.DeactivateEncryptionAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.ClientTest;
import de.rub.nds.tlstest.framework.annotations.DynamicValueConstraints;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.annotations.ScopeLimitations;
import de.rub.nds.tlstest.framework.annotations.TestDescription;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.annotations.categories.Compliance;
import de.rub.nds.tlstest.framework.annotations.categories.Handshake;
import de.rub.nds.tlstest.framework.annotations.categories.Interoperability;
import de.rub.nds.tlstest.framework.annotations.categories.Security;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.DerivationType;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import de.rub.nds.tlstest.suite.tests.client.both.statemachine.SharedStateMachineTest;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

/**
 * Contains tests to evaluate the target's state machine. Some test flows are based
 * on results found for TLS 1.2 servers in 
 * "Protocol State Fuzzing of TLS Implementations" (de Ruiter et al.)
 */
@Tag("statemachine")
@ClientTest
public class StateMachine extends Tls12Test {
    
    public boolean isNotAnonCipherSuite(CipherSuite cipherSuite) {
        return !cipherSuite.isAnon();
    }
    
    @TlsTest(description = "Omit the Certificate Message for non-anonymous Cipher Suite")
    @DynamicValueConstraints(affectedTypes = DerivationType.CIPHERSUITE, methods = "isNotAnonCipherSuite")
    @ScopeLimitations({DerivationType.CERTIFICATE})
    @Handshake(SeverityLevel.CRITICAL)
    @Compliance(SeverityLevel.CRITICAL)
    @Security(SeverityLevel.HIGH)
    public void omitCertificate(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        SendAction sendActionServerHelloBatch = (SendAction) workflowTrace.getFirstSendingAction();
        sendActionServerHelloBatch.getMessages().remove(1);
        
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));
        
        runner.execute(workflowTrace, config).validateFinal(Validator::receivedFatalAlert);
    }
    
    @TlsTest(description = "Omit the Change Cipher Spec Message and send Finished unencrypted")
    @Handshake(SeverityLevel.CRITICAL)
    @Compliance(SeverityLevel.CRITICAL)
    @Security(SeverityLevel.HIGH)
    public void omitChangeCipherSpecUnencryptedFinished(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        
        WorkflowTrace workflowTrace = runner.generateWorkflowTraceUntilSendingMessage(WorkflowTraceType.HANDSHAKE, ProtocolMessageType.CHANGE_CIPHER_SPEC);
        workflowTrace.addTlsAction(new SendAction(new FinishedMessage(config)));
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));
        
        runner.execute(workflowTrace, config).validateFinal(Validator::receivedFatalAlert);
    }
    
    @TlsTest(description = "Omit the Change Cipher Spec Message and send Finished encrypted")
    @Handshake(SeverityLevel.CRITICAL)
    @Compliance(SeverityLevel.CRITICAL)
    @Security(SeverityLevel.LOW)
    public void omitChangeCipherSpecEncryptedFinished(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        
        WorkflowTrace workflowTrace = runner.generateWorkflowTraceUntilSendingMessage(WorkflowTraceType.HANDSHAKE, ProtocolMessageType.CHANGE_CIPHER_SPEC);
        workflowTrace.addTlsAction(new ActivateEncryptionAction(false));
        workflowTrace.addTlsAction(new SendAction(new FinishedMessage(config)));
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));
        
        runner.execute(workflowTrace, config).validateFinal(Validator::receivedFatalAlert);
    }
    
    @TlsTest(description = "Send two Server Hellos as the first server messages")
    @Handshake(SeverityLevel.CRITICAL)
    @Compliance(SeverityLevel.CRITICAL)
    public void sendServerHelloTwice(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        SharedStateMachineTest.sharedSendServerHelloTwiceTest(config, runner);
    }
    
    @TlsTest(description = "Send a second ServerHello after the client's Finished has been received")
    @Handshake(SeverityLevel.CRITICAL)
    @Compliance(SeverityLevel.CRITICAL)
    public void sendSecondServerHelloAfterClientFinished(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace workflowTrace = runner.generateWorkflowTraceUntilSendingMessage(WorkflowTraceType.HANDSHAKE, HandshakeMessageType.FINISHED);
        ServerHelloMessage secondServerHello = new ServerHelloMessage(config);
        secondServerHello.setAdjustContext(false);
        workflowTrace.addTlsAction(new SendAction(secondServerHello));
        workflowTrace.addTlsAction(new ActivateEncryptionAction(false));
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));
        
        //There is no renegotiation in TLS 1.3 and TLS 1.2 requires a completed handshake
        //we aren't able to decrypt the alert here for OpenSSL
        runner.execute(workflowTrace, config).validateFinal(Validator::receivedFatalAlert);
    }
    
    @TlsTest(description = "Send ServerHello, Change CipherSpec")
    @Handshake(SeverityLevel.CRITICAL)
    @Compliance(SeverityLevel.CRITICAL)
    public void sendResumptionMessageFlow(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsAction(new ReceiveAction(new ClientHelloMessage()));
        workflowTrace.addTlsAction(new SendAction(new ServerHelloMessage(config), new ChangeCipherSpecMessage()));
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));
        
        runner.execute(workflowTrace, config).validateFinal(Validator::receivedFatalAlert);
    }
    
    @Test
    @TestDescription("Begin the Handshake with a Finished Message")
    @Handshake(SeverityLevel.CRITICAL)
    @Compliance(SeverityLevel.CRITICAL)
    public void beginWithFinished(WorkflowRunner runner) {
        Config config = getConfig();
        SharedStateMachineTest.sharedBeginWithFinishedTest(config, runner);
    }
    
    @Test
    @TestDescription("Begin the Handshake with Application Data")
    @Handshake(SeverityLevel.CRITICAL)
    @Compliance(SeverityLevel.CRITICAL)
    @Security(SeverityLevel.CRITICAL)
    public void beginWithApplicationData(WorkflowRunner runner) {
        Config config = getConfig();
        SharedStateMachineTest.sharedBeginWithApplicationDataTest(config, runner);
    }
}
