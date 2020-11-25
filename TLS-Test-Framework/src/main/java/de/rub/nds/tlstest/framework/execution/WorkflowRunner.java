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

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceMutator;
import de.rub.nds.tlsattacker.core.workflow.action.ReceivingAction;
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


    /**
     * Controls the test derivation. Setting everything to false disables the derivation.
     */
    // TODO: Delete these after migration
    @Deprecated
    public boolean replaceSupportedCiphersuites = false;
    @Deprecated
    public boolean appendEachSupportedCiphersuiteToClientSupported = false;
    @Deprecated
    public boolean respectConfigSupportedCiphersuites = false;
    @Deprecated
    public boolean replaceSelectedCiphersuite = false;
    @Deprecated
    public boolean useRecordFragmentationDerivation = true;
    @Deprecated
    public boolean useTCPFragmentationDerivation = true;

    
    private Config preparedConfig;

    private final TestMethodConfig testMethodConfig;
    private DerivationContainer derivationContainer;
    private WorkflowTraceType traceType;
    private HandshakeMessageType untilHandshakeMessage;
    private ProtocolMessageType untilProtocolMessage;
    private Boolean untilSendingMessage = null;
    private Boolean untilLast = false;


    public WorkflowRunner(ExtensionContext extensionContext) {
        this.context = TestContext.getInstance();
        this.extensionContext = extensionContext;
        this.testMethodConfig = new TestMethodConfig(extensionContext);
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
   @Deprecated
    public AnnotatedStateContainer execute(WorkflowTrace trace) {
        return this.execute(this.prepare(trace));
    }

    @Deprecated
    public AnnotatedStateContainer execute(AnnotatedStateContainer container) {
        return new AnnotatedStateContainer();
    }

    public AnnotatedState execute(WorkflowTrace trace, Config config) {
        return executeImmediately(trace, config);
    }

    public AnnotatedState executeImmediately(WorkflowTrace trace, Config config){
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
     * Public method to perform the test derivation and returning the states
     * in a AnnotatedStateContainer.
     *
     * @param trace base WorkflowTrace for the test derivation
     * @return AnnotatedStateContainer that contains the derived states
     */
    @Deprecated
    public AnnotatedStateContainer prepare(WorkflowTrace trace) {
        return new AnnotatedStateContainer();
    }

    @Deprecated
    public AnnotatedStateContainer prepare(WorkflowTrace trace, Config config) {
        return new AnnotatedStateContainer();
    }

    @Deprecated
    public AnnotatedStateContainer prepare(AnnotatedState annotatedState) {
        return new AnnotatedStateContainer();
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
        this.traceType = type;
        RunningModeType runningMode = RunningModeType.CLIENT;
        if (context.getConfig().getTestEndpointMode() == TestEndpointType.CLIENT) {
            runningMode = RunningModeType.SERVER;
        }
        WorkflowTrace trace = new WorkflowConfigurationFactory(preparedConfig).createWorkflowTrace(traceType, runningMode);
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

    @Deprecated
    public Function<AnnotatedState, AnnotatedState> getStateModifier() {
        return null;
    }

    @Deprecated
    public void setStateModifier(Function<AnnotatedState, AnnotatedState> stateModifier) {

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
}
