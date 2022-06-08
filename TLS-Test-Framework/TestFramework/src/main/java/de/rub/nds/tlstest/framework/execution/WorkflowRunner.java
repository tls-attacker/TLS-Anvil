/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * Copyright 2022 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.execution;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.NewSessionTicketMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.TlsMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.record.layer.RecordLayerFactory;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceMutator;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceivingAction;
import de.rub.nds.tlsattacker.core.workflow.action.ResetConnectionAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsattacker.core.workflow.task.StateExecutionTask;
import de.rub.nds.tlsattacker.core.workflow.task.TlsTask;
import de.rub.nds.tlsattacker.transport.TransportHandlerType;
import de.rub.nds.tlsattacker.transport.tcp.ServerTcpTransportHandler;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.constants.KeyX;
import de.rub.nds.tlstest.framework.constants.TestEndpointType;
import de.rub.nds.tlstest.framework.model.DerivationContainer;
import de.rub.nds.tlstest.framework.model.DerivationType;
import de.rub.nds.tlstest.framework.utils.TestMethodConfig;
import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.extension.ExtensionContext;

import javax.annotation.Nonnull;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.function.Function;
import java.util.logging.Level;
import java.util.stream.Collectors;

/**
 * An object of this class is passed to every test method, it is created by the
 * WorkflowRunnerResolver class
 */
public class WorkflowRunner {
    private static final Logger LOGGER = LogManager.getLogger();
    private TestContext context = null;
    private ExtensionContext extensionContext = null;
    
    private Config preparedConfig;

    private DerivationContainer derivationContainer;
    private HandshakeMessageType untilHandshakeMessage;
    private ProtocolMessageType untilProtocolMessage;
    private Boolean untilSendingMessage = null;
    private Boolean untilLast = false;
    private Boolean autoHelloRetryRequest = true;


    public WorkflowRunner(ExtensionContext extensionContext) {
        this.context = TestContext.getInstance();
        this.extensionContext = extensionContext;
    }
    
    public WorkflowRunner(ExtensionContext extensionContext, Config config) {
        this(extensionContext);
        this.preparedConfig = config;
    }

    /**
     * Executes a WorkflowTrace.
     * It performs the derivation and executes each derived handshake.
     *
     * @param trace Trace to execute
     * @return
     */
    public AnnotatedState execute(WorkflowTrace trace, Config config) {
        if(preparedConfig == null) {
            LOGGER.warn("Config was not set before execution - WorkflowTrace may me invalid for Test:" + extensionContext.getRequiredTestMethod().getName());
            preparedConfig = config;
        }
        
        if(shouldInsertHelloRetryRequest()) {
            insertHelloRetryRequest(trace, config.getDefaultSelectedNamedGroup());
        }
        
        if(shouldInsertNewSessionTicket()) {
            insertTls12NewSessionTicket(trace);
        }
        
        if(preparedConfig.getHighestProtocolVersion() == ProtocolVersion.TLS13
                && context.getConfig().getTestEndpointMode() == TestEndpointType.SERVER) {
            allowOptionalTls13NewSessionTickets(trace);
            disableQuickReceiveForTls13PostHandshakeServerTests(trace, config);
        } else if(preparedConfig.getHighestProtocolVersion() == ProtocolVersion.TLS13
                && context.getConfig().getTestEndpointMode() == TestEndpointType.CLIENT) {
            allowOptionalClientCcs(trace);
        }
        
        allowOptionalClientApplicationMessage(trace);
        
        AnnotatedState annotatedState = new AnnotatedState(extensionContext, new State(config, trace), derivationContainer);

        if (context.getConfig().getTestEndpointMode() == TestEndpointType.SERVER) {
            StateExecutionTask task = new StateExecutionTask(annotatedState.getState(), context.getStateExecutor().getReexecutions());
            TestContext.getInstance().increaseServerHandshakesSinceRestart();
            if(TestContext.getInstance().getServerHandshakesSinceRestart() == TestContext.getInstance().getConfig().getRestartServerAfter()
                    && TestContext.getInstance().getConfig().getTimeoutActionScript() != null) {
                LOGGER.info("Scheduling server restart with task");
                task.setBeforeTransportPreInitCallback((State state) -> {
                    try {
                        return TestContext.getInstance().getConfig().getTimeoutActionScript().call();
                    } catch (Exception ex) {
                        LOGGER.error(ex);
                        return 1;
                    }
                });
                TestContext.getInstance().resetServerHandshakesSinceRestart();
            }
            context.getStateExecutor().bulkExecuteTasks(task);
        } else {
            try {
                annotatedState.getState().getTlsContext().setTransportHandler(new ServerTcpTransportHandler(context.getConfig().getConnectionTimeout(), context.getConfig().getConnectionTimeout(), context.getConfig().getTestClientDelegate().getServerSocket()));
                annotatedState.getState().getTlsContext().setRecordLayer(RecordLayerFactory.getRecordLayer(annotatedState.getState().getTlsContext().getRecordLayerType(), annotatedState.getState().getTlsContext()));
                StateExecutionTask task = new StateExecutionTask(annotatedState.getState(), 2);
                
                task.setBeforeTransportInitCallback(context.getConfig().getTestClientDelegate().getTriggerScript());
                context.getStateExecutor().bulkExecuteTasks(task);
            } catch (IOException ex) {
                throw new RuntimeException("Failed to set TransportHandler");
            }
        }

        return annotatedState;
    }

    /**
     * Configures the WorkflowRunner to use the WorkflowConfigurationFactory to generate workflow traces.
     * The workflows are generated when the buildFinalState is called.
     * This function is called when the derivation is executed.
     *
     * @param type WorkflowTraceType that should be used for the generated workflowTrace
     * @return empty WorkflowTrace
     */
    public WorkflowTrace generateWorkflowTrace(@Nonnull WorkflowTraceType type) {
        RunningModeType runningMode = RunningModeType.CLIENT;
        if (context.getConfig().getTestEndpointMode() == TestEndpointType.CLIENT) {
            runningMode = RunningModeType.SERVER;
        }
        WorkflowTrace trace = new WorkflowConfigurationFactory(preparedConfig).createWorkflowTrace(type, runningMode);
        if (this.untilHandshakeMessage != null)
                WorkflowTraceMutator.truncateAt(trace, this.untilHandshakeMessage, this.untilSendingMessage, untilLast);
            if (this.untilProtocolMessage != null)
                WorkflowTraceMutator.truncateAt(trace, this.untilProtocolMessage, this.untilSendingMessage, untilLast);
        return trace;
    }

    public WorkflowTrace generateWorkflowTraceUntilMessage(@Nonnull WorkflowTraceType type, @Nonnull HandshakeMessageType handshakeMessageType) {
        this.untilHandshakeMessage = handshakeMessageType;
        this.untilProtocolMessage = null;

        return generateWorkflowTrace(type);
    }

    public WorkflowTrace generateWorkflowTraceUntilMessage(@Nonnull WorkflowTraceType type, @Nonnull ProtocolMessageType protocolMessageType) {
        this.untilHandshakeMessage = null;
        this.untilProtocolMessage = protocolMessageType;

        return generateWorkflowTrace(type);
    }

    public WorkflowTrace generateWorkflowTraceUntilSendingMessage(@Nonnull WorkflowTraceType type, @Nonnull HandshakeMessageType handshakeMessageType) {
        this.untilHandshakeMessage = handshakeMessageType;
        this.untilProtocolMessage = null;
        this.untilSendingMessage = true;

        return generateWorkflowTrace(type);
    }

    public WorkflowTrace generateWorkflowTraceUntilSendingMessage(@Nonnull WorkflowTraceType type, @Nonnull ProtocolMessageType protocolMessageType) {
        this.untilHandshakeMessage = null;
        this.untilProtocolMessage = protocolMessageType;
        this.untilSendingMessage = true;

        return generateWorkflowTrace(type);
    }

    public WorkflowTrace generateWorkflowTraceUntilReceivingMessage(@Nonnull WorkflowTraceType type, @Nonnull HandshakeMessageType handshakeMessageType) {
        this.untilHandshakeMessage = handshakeMessageType;
        this.untilProtocolMessage = null;
        this.untilSendingMessage = false;

        return generateWorkflowTrace(type);
    }

    public WorkflowTrace generateWorkflowTraceUntilReceivingMessage(@Nonnull WorkflowTraceType type, @Nonnull ProtocolMessageType protocolMessageType) {
        this.untilHandshakeMessage = null;
        this.untilProtocolMessage = protocolMessageType;
        this.untilSendingMessage = false;

        return generateWorkflowTrace(type);
    }
    
    public WorkflowTrace generateWorkflowTraceUntilLastMessage(@Nonnull WorkflowTraceType type, @Nonnull HandshakeMessageType handshakeMessageType) {
        this.untilHandshakeMessage = handshakeMessageType;
        this.untilProtocolMessage = null;
        this.untilLast = true;

        return generateWorkflowTrace(type);
    }

    public WorkflowTrace generateWorkflowTraceUntilLastMessage(@Nonnull WorkflowTraceType type, @Nonnull ProtocolMessageType protocolMessageType) {
        this.untilHandshakeMessage = null;
        this.untilProtocolMessage = protocolMessageType;
        this.untilLast = true;
        
        return generateWorkflowTrace(type);
    }

    public WorkflowTrace generateWorkflowTraceUntilLastSendingMessage(@Nonnull WorkflowTraceType type, @Nonnull HandshakeMessageType handshakeMessageType) {
        this.untilHandshakeMessage = handshakeMessageType;
        this.untilProtocolMessage = null;
        this.untilSendingMessage = true;
        this.untilLast = true;

        return generateWorkflowTrace(type);
    }

    public WorkflowTrace generateWorkflowTraceUntilLastSendingMessage(@Nonnull WorkflowTraceType type, @Nonnull ProtocolMessageType protocolMessageType) {
        this.untilHandshakeMessage = null;
        this.untilProtocolMessage = protocolMessageType;
        this.untilSendingMessage = true;
        this.untilLast = true;

        return generateWorkflowTrace(type);
    }

    public WorkflowTrace generateWorkflowTraceUntilLastReceivingMessage(@Nonnull WorkflowTraceType type, @Nonnull HandshakeMessageType handshakeMessageType) {
        this.untilHandshakeMessage = handshakeMessageType;
        this.untilProtocolMessage = null;
        this.untilSendingMessage = false;
        this.untilLast = true;

        return generateWorkflowTrace(type);
    }

    public WorkflowTrace generateWorkflowTraceUntilLastReceivingMessage(@Nonnull WorkflowTraceType type, @Nonnull ProtocolMessageType protocolMessageType) {
        this.untilHandshakeMessage = null;
        this.untilProtocolMessage = protocolMessageType;
        this.untilSendingMessage = false;
        this.untilLast = true;

        return generateWorkflowTrace(type);
    }


    public ExtensionContext getExtensionContext() {
        return extensionContext;
    }

    public void setExtensionContext(ExtensionContext extensionContext) {
        this.extensionContext = extensionContext;
    }
    
    public Config getPreparedConfig() {
        return preparedConfig;
    }

    public void setPreparedConfig(Config preparedConfig) {
        this.preparedConfig = preparedConfig;
    }

    public DerivationContainer getDerivationContainer() {
        return derivationContainer;
    }

    public void setDerivationContainer(DerivationContainer derivationContainer) {
        this.derivationContainer = derivationContainer;
    }
    
    public boolean shouldInsertHelloRetryRequest(){
        if(!autoHelloRetryRequest 
                || context.getConfig().getTestEndpointMode() == TestEndpointType.SERVER
                || preparedConfig.getHighestProtocolVersion() != ProtocolVersion.TLS13
                || !context.getSiteReport().getSupportedNamedGroups().contains(preparedConfig.getDefaultSelectedNamedGroup())
                || context.getSiteReport().getClientHelloKeyShareGroups().contains(preparedConfig.getDefaultSelectedNamedGroup())) {
            return false;
        }
        return true;
    }
    
    private boolean shouldInsertNewSessionTicket() {
        if(context.getConfig().getTestEndpointMode() == TestEndpointType.SERVER
                && preparedConfig.getHighestProtocolVersion() == ProtocolVersion.TLS12
                && preparedConfig.isAddSessionTicketTLSExtension()) {
            return true;
        }
        return false;
    }
    
    public void insertTls12NewSessionTicket(WorkflowTrace trace) {
        ReceiveAction receiveChangeCipherSpec = (ReceiveAction) WorkflowTraceUtil.getFirstReceivingActionForMessage(ProtocolMessageType.CHANGE_CIPHER_SPEC, trace);
        
        //not all WorkflowTraces reach a ChangeCipherSpec
        if(receiveChangeCipherSpec != null) {
            NewSessionTicketMessage newSessionTicket = new NewSessionTicketMessage();
            newSessionTicket.setRequired(false);
            receiveChangeCipherSpec.getExpectedMessages().add(0, newSessionTicket);
        }
    }
    
    public void insertHelloRetryRequest(WorkflowTrace trace, NamedGroup requestedGroup) {
        ClientHelloMessage failingClientHello = new ClientHelloMessage();
        ServerHelloMessage helloRetryRequest = new ServerHelloMessage(preparedConfig);
        helloRetryRequest.setRandom(Modifiable.explicit(ServerHelloMessage.getHelloRetryRequestRandom()));
        
        if(requestedGroup != preparedConfig.getDefaultSelectedNamedGroup() && helloRetryRequest.containsExtension(ExtensionType.KEY_SHARE)) {
            KeyShareExtensionMessage keyShareExtension = helloRetryRequest.getExtension(KeyShareExtensionMessage.class);
            keyShareExtension.setKeyShareListBytes(Modifiable.explicit(requestedGroup.getValue()));
        }
        
        trace.getTlsActions().add(0, new SendAction(helloRetryRequest));
        trace.getTlsActions().add(0, new ReceiveAction(failingClientHello));
        
        ChangeCipherSpecMessage compatibilityCCS = new ChangeCipherSpecMessage();
        compatibilityCCS.setRequired(false);
        //OpenSSL sends  ChangeCipherSpec || ClientHello upon HelloRetry
        ((ReceiveAction)trace.getTlsActions().get(2)).getExpectedMessages().add(0, compatibilityCCS);        
    } 
    
    public void allowOptionalTls13NewSessionTickets(WorkflowTrace trace) {
        boolean mayReceiveNewSessionTicketFromNow = false;
        ReceiveAction lastReceive = null;
        for(TlsAction action : trace.getTlsActions()) {
            if(action instanceof ReceiveAction) {
                ReceiveAction receiveAction = (ReceiveAction) action;
                lastReceive = receiveAction;
                if(receiveAction.getExpectedMessages().stream().anyMatch(message -> message instanceof FinishedMessage)) {
                    mayReceiveNewSessionTicketFromNow = true;
                }
                
                //set explicitly expected new session tickets as optional to
                //allow early NewSessionTickets sent with Fin
                receiveAction.getExpectedMessages().stream().filter(message -> message instanceof NewSessionTicketMessage)
                        .forEach(newSessionTicket -> newSessionTicket.setRequired(false));
                if(mayReceiveNewSessionTicketFromNow) {
                    receiveAction.getActionOptions().add(ActionOption.IGNORE_UNEXPECTED_NEW_SESSION_TICKETS);
                }
            } else if(action instanceof ResetConnectionAction) {
                mayReceiveNewSessionTicketFromNow = false;
            }
        }
        
        //add an optional NewSessionTicketMessage for Alert receiving action
        //this facilitates the tolerance mechanisms of the Validator
        if(lastReceive != null && lastReceive.getExpectedMessages() != null 
                && lastReceive.getExpectedMessages().stream().anyMatch(message -> ((TlsMessage)message).getProtocolMessageType() == ProtocolMessageType.ALERT)
                && mayReceiveNewSessionTicketFromNow) {
            NewSessionTicketMessage optionalExplicitNewSessionTicket = new NewSessionTicketMessage();
            optionalExplicitNewSessionTicket.setRequired(false);
            lastReceive.getExpectedMessages().add(0, optionalExplicitNewSessionTicket);
        }
    }
    
    public void allowOptionalClientCcs(WorkflowTrace trace) {
        boolean ccsAlreadyExpected = false;
        for(ReceivingAction receiving : trace.getReceivingActions()) {
            if(receiving instanceof ReceiveAction) {
                ReceiveAction receiveAction = (ReceiveAction) receiving;
                if(receiveAction.getGoingToReceiveProtocolMessageTypes().contains(ProtocolMessageType.CHANGE_CIPHER_SPEC)) {
                    ccsAlreadyExpected = true;
                }
            }
        }
        
        //this will only affect alerts expected during the handshake as we allways
        //add an optional css beforehand otherwise
        if(trace.getLastReceivingAction() != null 
                && trace.getLastReceivingAction() instanceof ReceiveAction
                && !ccsAlreadyExpected
                && ((ReceiveAction)trace.getLastReceivingAction()).getGoingToReceiveProtocolMessageTypes().contains(ProtocolMessageType.ALERT)) {
            ReceiveAction lastReceive = (ReceiveAction) trace.getLastReceivingAction();
            ChangeCipherSpecMessage optionalCcs = new ChangeCipherSpecMessage();
            optionalCcs.setRequired(false);
            lastReceive.getExpectedMessages().add(0, optionalCcs);
        }
    }
    
    public void allowOptionalClientApplicationMessage(WorkflowTrace trace) {
        if(context.getConfig().getTestEndpointMode() == TestEndpointType.CLIENT) {
            boolean mayReceiveApplicationDataFromNow = false;
            for(TlsAction action : trace.getTlsActions()) {
                if(action instanceof ReceiveAction) {
                    ReceiveAction receiveAction = (ReceiveAction) action;
                    if(receiveAction.getExpectedMessages().stream().anyMatch(message -> message instanceof FinishedMessage)
                            && preparedConfig.getHighestProtocolVersion() == ProtocolVersion.TLS13) {
                        mayReceiveApplicationDataFromNow = true;
                    
                        //only allow *after* Finished
                        ApplicationMessage optionalAppMsg = new ApplicationMessage();
                        optionalAppMsg.setRequired(false);
                        receiveAction.getExpectedMessages().add(optionalAppMsg);
                    } else {
                        if(mayReceiveApplicationDataFromNow) {
                            ApplicationMessage optionalAppMsg = new ApplicationMessage();
                            optionalAppMsg.setRequired(false);
                            receiveAction.getExpectedMessages().add(0, optionalAppMsg);
                        }
                    }
                
                } else if(action instanceof ResetConnectionAction) {
                    mayReceiveApplicationDataFromNow = false;
                } else if(action instanceof SendAction && preparedConfig.getHighestProtocolVersion() != ProtocolVersion.TLS13) {
                    SendAction sendAction = (SendAction) action;
                    if(sendAction.getSendMessages().stream().anyMatch(message -> message instanceof FinishedMessage)) {
                        mayReceiveApplicationDataFromNow = true;
                    }
                }
            }
        }
    }
    
    /**
     * TLS 1.3 servers may always send a NewSessionTicket message first
     * this could interfere with a Receive Action that waits for an Alert if
     * quick receive is set in Config.
     */
    public void disableQuickReceiveForTls13PostHandshakeServerTests(WorkflowTrace trace, Config config) {
        List<ReceivingAction> receivingActions = trace.getReceivingActions();
        ReceivingAction receiveFinished = (ReceivingAction) WorkflowTraceUtil.getFirstReceivingActionForMessage(HandshakeMessageType.FINISHED, trace);
        if(receiveFinished != null && receivingActions.indexOf(receiveFinished) < receivingActions.size() - 1) {
            config.setQuickReceive(false);
        }            
    }

    public Boolean isAutoHelloRetryRequest() {
        return autoHelloRetryRequest;
    }

    public void setAutoHelloRetryRequest(Boolean autoHelloRetryRequest) {
        this.autoHelloRetryRequest = autoHelloRetryRequest;
    }
}
