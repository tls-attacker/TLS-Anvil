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
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.ResetConnectionAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.ServerTest;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.constants.TestStatus;
import de.rub.nds.tlstest.framework.execution.AnnotatedStateContainer;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import java.util.Arrays;
import org.junit.jupiter.api.Tag;

import static org.junit.Assert.assertTrue;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

@ServerTest
@Tag("alert")
@Execution(ExecutionMode.SAME_THREAD)
public class AlertProtocol extends Tls12Test {

    @TlsTest(description = "Unless some other fatal alert has been transmitted, each party is " +
            "required to send a close_notify alert before closing the write side " +
            "of the connection. The other party MUST respond with a close_notify " +
            "alert of its own and close down the connection immediately, " +
            "discarding any pending writes.")
    @RFC(number = 5264, section = "7.2.1 Closure Alerts")
    public void close_notify(WorkflowRunner runner) {
        Config c = this.getConfig();
        runner.replaceSupportedCiphersuites = true;

        AlertMessage alert = new AlertMessage();
        alert.setLevel(Modifiable.explicit(AlertLevel.WARNING.getValue()));
        alert.setDescription(Modifiable.explicit(AlertDescription.CLOSE_NOTIFY.getValue()));

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                new SendAction(new ClientHelloMessage(c)),
                new ReceiveTillAction(new ServerHelloDoneMessage()),
                new SendAction(alert),
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(workflowTrace, c).validateFinal(i -> {
            WorkflowTrace trace = i.getWorkflowTrace();
            assertTrue("Workflow could not be executed as planned", Validator.smartExecutedAsPlanned(trace));

            AlertMessage message = trace.getLastReceivedMessage(AlertMessage.class);
            if (message == null) {
                i.addAdditionalResultInfo("No close_notify alert received.");
                i.setStatus(TestStatus.PARTIALLY_SUCCEEDED);
                return;
            }
            Validator.receivedWarningAlert(i);
            Validator.testAlertDescription(i, AlertDescription.CLOSE_NOTIFY, message);

        });
    }


    @TlsTest(description = "Thus, any connection terminated with a fatal alert MUST NOT be resumed.", securitySeverity = SeverityLevel.CRITICAL)
    @RFC(number = 5264, section = "7.2.2 Error Alerts")
    public void abortAfterFatalAlert_sendBeforeCCS(WorkflowRunner runner) {
        Config c = this.getConfig();
        runner.generateWorkflowTraceUntilSendingMessage(WorkflowTraceType.HANDSHAKE, ProtocolMessageType.CHANGE_CIPHER_SPEC);

        AnnotatedStateContainer container = new AnnotatedStateContainer();
        for (AlertDescription i : AlertDescription.values()) {
            AlertMessage alert = new AlertMessage();
            alert.setLevel(Modifiable.explicit(AlertLevel.FATAL.getValue()));
            alert.setDescription(Modifiable.explicit(i.getValue()));

            WorkflowTrace workflowTrace = new WorkflowTrace();
            workflowTrace.addTlsActions(
                    new SendAction(alert),
                    new SendAction(true, new ChangeCipherSpecMessage(), new FinishedMessage()),
                    new ReceiveAction(new AlertMessage())
            );

            runner.setStateModifier(s -> {
                s.addAdditionalTestInfo(i.name());
                return null;
            });
            container.addAll(runner.prepare(workflowTrace, c));
        }

        runner.execute(container).validateFinal(Validator::receivedFatalAlert);
    }
    

    @TlsTest(description = "Thus, any connection terminated with a fatal alert MUST NOT be resumed.", securitySeverity = SeverityLevel.CRITICAL)
    @RFC(number = 5264, section = "7.2.2 Error Alerts")
    public void abortAfterFatalAlert_sendAfterServerHelloDone(WorkflowRunner runner) {
        Config c = this.getConfig();
        runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        
        AnnotatedStateContainer container = new AnnotatedStateContainer();
        for (AlertDescription i : AlertDescription.values()) {
            AlertMessage alert = new AlertMessage();
            alert.setLevel(Modifiable.explicit(AlertLevel.FATAL.getValue()));
            alert.setDescription(Modifiable.explicit(i.getValue()));

            WorkflowTrace workflowTrace = new WorkflowTrace();
            workflowTrace.addTlsActions(
                    new SendAction(alert),
                    new ReceiveAction(new AlertMessage())
            );

            runner.setStateModifier(s -> {
                s.addAdditionalTestInfo(i.name());
                return null;
            });
            container.addAll(runner.prepare(workflowTrace, c));
        }

        runner.execute(container).validateFinal(Validator::receivedFatalAlert);
    }
    
    @TlsTest(description = "Thus, any connection terminated with a fatal alert MUST NOT be resumed.", securitySeverity = SeverityLevel.CRITICAL)
    @RFC(number = 5264, section = "7.2.2 Error Alerts")
    @Tag("WIP")
    public void rejectResumptionAfterFatalPostHandshake(WorkflowRunner runner) {
        Config c = this.getConfig();
        runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        
        AnnotatedStateContainer container = new AnnotatedStateContainer();
        for (AlertDescription i : AlertDescription.values()) {
            WorkflowTrace workflowTrace = new WorkflowTrace();
        
            AlertMessage alert = new AlertMessage();
            alert.setLevel(Modifiable.explicit(AlertLevel.FATAL.getValue()));
            alert.setDescription(Modifiable.explicit(i.getValue()));
        
            workflowTrace.addTlsActions(
                    new SendAction(alert),
                    new ResetConnectionAction()
            );
        
            runner.setStateModifier(s -> {
                s.addAdditionalTestInfo(i.name());
                CipherSuite cipherSuite = s.getInspectedCipherSuite();
                Config dummyConfig = c.createCopy();
                dummyConfig.setDefaultSelectedCipherSuite(cipherSuite);
            
                WorkflowTrace secondHandshake = new WorkflowConfigurationFactory(dummyConfig).createWorkflowTrace(WorkflowTraceType.RESUMPTION, s.getState().getRunningMode());
                s.getWorkflowTrace().addTlsActions(secondHandshake.getTlsActions().get(0),
                    secondHandshake.getTlsActions().get(1));
                return null;
            });
            
            container.addAll(runner.prepare(workflowTrace, c));
        }
        runner.execute(container).validateFinal(s -> {
            WorkflowTrace trace = s.getWorkflowTrace();
            ClientHelloMessage cHello = trace.getLastSendMessage(ClientHelloMessage.class);
            if(WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, trace) 
                    &&  trace.getLastReceivedMessage(ServerHelloMessage.class) != trace.getFirstReceivedMessage(ServerHelloMessage.class)) {
                ServerHelloMessage sHello = trace.getLastReceivedMessage(ServerHelloMessage.class);
                assertTrue(!Arrays.equals(cHello.getSessionId().getValue(), sHello.getSessionId().getValue()));
            }
        });
    }
    
    @TlsTest(description = "Thus, any connection terminated with a fatal alert MUST NOT be resumed.", securitySeverity = SeverityLevel.CRITICAL)
    @RFC(number = 5264, section = "7.2.2 Error Alerts")
    @Tag("WIP")
    public void rejectResumptionAfterInvalidFinished(WorkflowRunner runner) {
        Config c = this.getConfig();
        runner.replaceSupportedCiphersuites = true;
        runner.generateWorkflowTraceUntilSendingMessage(WorkflowTraceType.HANDSHAKE, HandshakeMessageType.FINISHED);
        
        WorkflowTrace workflowTrace = new WorkflowTrace();
            
        FinishedMessage finishedMessage = new FinishedMessage();
        finishedMessage.setVerifyData(Modifiable.xor(new byte[]{0x01}, 0));
        
        workflowTrace.addTlsActions(
                new SendAction(finishedMessage),
                new ResetConnectionAction()
        );
        
       runner.setStateModifier(s -> {
            CipherSuite cipherSuite = s.getInspectedCipherSuite();
            Config dummyConfig = c.createCopy();
            dummyConfig.setDefaultSelectedCipherSuite(cipherSuite);
            
            WorkflowTrace secondHandshake = new WorkflowConfigurationFactory(dummyConfig).createWorkflowTrace(WorkflowTraceType.RESUMPTION, s.getState().getRunningMode());
            s.getWorkflowTrace().addTlsActions(secondHandshake.getTlsActions().get(0),
                secondHandshake.getTlsActions().get(1));
            return null;
        });
        
        runner.execute(workflowTrace, c).validateFinal(s -> {
            WorkflowTrace trace = s.getWorkflowTrace();
            ClientHelloMessage cHello = trace.getLastSendMessage(ClientHelloMessage.class);
            if(WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, trace) 
                    &&  trace.getLastReceivedMessage(ServerHelloMessage.class) != trace.getFirstReceivedMessage(ServerHelloMessage.class)) {
                ServerHelloMessage sHello = trace.getLastReceivedMessage(ServerHelloMessage.class);
                assertTrue(!Arrays.equals(cHello.getSessionId().getValue(), sHello.getSessionId().getValue()));
            }
        });
    }
}


