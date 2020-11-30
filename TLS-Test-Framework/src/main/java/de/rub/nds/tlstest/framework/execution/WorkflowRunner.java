/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.execution;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceMutator;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceivingAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsattacker.core.workflow.task.StateExecutionServerTask;
import de.rub.nds.tlsattacker.core.workflow.task.TlsTask;
import de.rub.nds.tlsattacker.transport.TransportHandlerType;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.constants.KeyX;
import de.rub.nds.tlstest.framework.constants.TestEndpointType;
import de.rub.nds.tlstest.framework.model.DerivationContainer;
import de.rub.nds.tlstest.framework.model.DerivationType;
import de.rub.nds.tlstest.framework.utils.TestMethodConfig;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.extension.ExtensionContext;

import javax.annotation.Nonnull;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.function.Function;
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
        if(shouldInsertHelloRetryRequest()) {
            insertHelloRetryRequest(trace, config.getDefaultSelectedNamedGroup());
        }
        
        AnnotatedState annotatedState = new AnnotatedState(extensionContext, new State(config, trace), derivationContainer);

        if (context.getConfig().getTestEndpointMode() == TestEndpointType.SERVER) {
            context.getStateExecutor().bulkExecuteClientStateTasks(annotatedState.getState());
        } else {
            StateExecutionServerTask task = new StateExecutionServerTask(annotatedState.getState(), context.getConfig().getTestClientDelegate().getServerSocket(), 2);
            task.setBeforeAcceptCallback(context.getConfig().getTestClientDelegate().getTriggerScript());
            context.getStateExecutor().bulkExecuteTasks(task);
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
    
    private boolean shouldInsertHelloRetryRequest(){
        if(!autoHelloRetryRequest 
                || context.getConfig().getTestEndpointMode() == TestEndpointType.SERVER
                || preparedConfig.getHighestProtocolVersion() != ProtocolVersion.TLS13
                || !context.getSiteReport().getSupportedNamedGroups().contains(preparedConfig.getDefaultSelectedNamedGroup())
                || context.getSiteReport().getClientHelloKeyShareGroups().contains(preparedConfig.getDefaultSelectedNamedGroup())) {
            return false;
        }
        return true;
    }
    
    public void insertHelloRetryRequest(WorkflowTrace trace, NamedGroup requestedGroup) {
        ClientHelloMessage failingClientHello = new ClientHelloMessage();
        ServerHelloMessage helloRetryRequest = new ServerHelloMessage(preparedConfig);
        helloRetryRequest.setRandom(Modifiable.explicit(ServerHelloMessage.getHelloRetryRequestRandom()));
        
        trace.getTlsActions().add(0, new SendAction(helloRetryRequest));
        trace.getTlsActions().add(0, new ReceiveAction(failingClientHello));
        
        if(preparedConfig.getTls13BackwardsCompatibilityMode()) {
            ChangeCipherSpecMessage compatibilityCCS = new ChangeCipherSpecMessage();
            compatibilityCCS.setRequired(false);
            //OpenSSL sends  ChangeCipherSpec || ClientHello upon HelloRetry
            ((ReceiveAction)trace.getTlsActions().get(2)).getExpectedMessages().add(0, compatibilityCCS); 
        }        
    } 

    public Boolean isAutoHelloRetryRequest() {
        return autoHelloRetryRequest;
    }

    public void setAutoHelloRetryRequest(Boolean autoHelloRetryRequest) {
        this.autoHelloRetryRequest = autoHelloRetryRequest;
    }
}
