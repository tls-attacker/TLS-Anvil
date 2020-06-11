package de.rub.nds.tlstest.framework.execution;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceMutator;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsattacker.core.workflow.task.StateExecutionServerTask;
import de.rub.nds.tlsattacker.core.workflow.task.TlsTask;
import de.rub.nds.tlsattacker.transport.TransportHandlerType;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.constants.TestEndpointType;
import de.rub.nds.tlstest.framework.utils.TestMethodConfig;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.extension.ExtensionContext;

import javax.annotation.Nonnull;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.function.Function;
import java.util.stream.Collectors;

public class WorkflowRunner {
    private static final Logger LOGGER = LogManager.getLogger();
    private TestContext context = null;
    private ExtensionContext extensionContext = null;

    public boolean replaceSupportedCiphersuites = false;
    public boolean appendEachSupportedCiphersuiteToClientSupported = false;
    public boolean respectConfigSupportedCiphersuites = false;

    public boolean replaceSelectedCiphersuite = false;

    public boolean useRecordFragmentationDerivation = true;
    public boolean useTCPFragmentationDerivation = true;



    private TestMethodConfig testMethodConfig;
    private WorkflowTraceType traceType;
    private HandshakeMessageType untilHandshakeMessage;
    private ProtocolMessageType untilProtocolMessage;
    private Boolean untilSendingMessage = null;

    private Function<AnnotatedState, AnnotatedState> stateModifier = null;


    public WorkflowRunner(TestContext context) {
        this.context = context;
    }

    public AnnotatedStateContainer execute(WorkflowTrace trace) {
        return this.execute(this.prepare(trace));
    }

    public AnnotatedStateContainer execute(WorkflowTrace trace, Config config) {
        return this.execute(this.prepare(trace, config));
    }

    public AnnotatedStateContainer execute(AnnotatedStateContainer container) {
        List<AnnotatedState> toAdd = new ArrayList<>();

        if (container.getStates().size() == 0) {
            LOGGER.warn("AnnotatedStateContainer does not contain any state. No Handshake will be performed...");
        }

        for (AnnotatedState i : container.getStates()) {
            if (!useTCPFragmentationDerivation && !useRecordFragmentationDerivation)
                break;


            if (useRecordFragmentationDerivation) {
                AnnotatedState copy = new AnnotatedState(i);
                copy.setParentUUID(i.getUuid());

                copy.getState().getConfig().setDefaultMaxRecordData(50);
                copy.addTransformationDescription("Record fragmentation");

                toAdd.add(copy);
            }

            if (useTCPFragmentationDerivation) {
                AnnotatedState copy = new AnnotatedState(i);
                copy.setParentUUID(i.getUuid());

                copy.getState().getConfig().getDefaultClientConnection().setTransportHandlerType(TransportHandlerType.TCP_FRAGMENTATION);
                copy.getState().getConfig().getDefaultServerConnection().setTransportHandlerType(TransportHandlerType.TCP_FRAGMENTATION);
                copy.getWorkflowTrace().setConnections(null);
                copy.getState().reset();

                copy.addTransformationDescription("TCP fragmentation");
                toAdd.add(copy);
            }

        }

        container.getStates().addAll(toAdd);

        container.setUniqueId(extensionContext.getUniqueId());
        container.setTestMethodConfig(testMethodConfig);

        List<State> states = container.getStates().parallelStream().map(AnnotatedState::getState).collect(Collectors.toList());
        if (context.getConfig().getTestEndpointMode() == TestEndpointType.SERVER) {
            context.getTestRunner().getExecutor().bulkExecuteStateTasks(states);
        } else {
            List<TlsTask> tasks = states.stream().map(i -> {
                StateExecutionServerTask task = new StateExecutionServerTask(i, context.getConfig().getTestClientDelegate().getServerSocket(), 2);
                task.setBeforeAcceptCallback(() -> {
                    context.getConfig().getTestClientDelegate().executeWakeupScript();
                });
                return task;
            }).collect(Collectors.toList());
            context.getTestRunner().getExecutor().bulkExecuteTasks(tasks);
        }


        return container;
    }



    public AnnotatedStateContainer prepare(WorkflowTrace trace) {
        Config config = this.context.getConfig().createConfig();
        if (testMethodConfig.getTlsVersion().supported() == ProtocolVersion.TLS13) {
            config = this.context.getConfig().createTls13Config();
        }
        return this.prepare(trace, config);
    }

    public AnnotatedStateContainer prepare(WorkflowTrace trace, Config config) {
        AnnotatedState annotatedState = new AnnotatedState(new State(config, trace));
        return this.prepare(annotatedState);
    }

    public AnnotatedStateContainer prepare(AnnotatedState annotatedState) {
        return new AnnotatedStateContainer(extensionContext.getUniqueId(), testMethodConfig, this.transformState(annotatedState));
    }


    public WorkflowTrace generateWorkflowTrace(@Nonnull WorkflowTraceType type) {
        this.traceType = type;
        // just return an empty trace, the real trace is generated and merged in the transform functions,
        // because the ciphersuite needs to be known for this.
        return new WorkflowTrace();
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

    private List<AnnotatedState> transformStateClientTest(AnnotatedState annotatedState) {
        List<AnnotatedState> result = new ArrayList<AnnotatedState>(){};
        List<CipherSuite> supported;
        State state = annotatedState.getState();
        Config inputConfig = annotatedState.getState().getConfig();

        if (inputConfig.getHighestProtocolVersion() != ProtocolVersion.TLS13) {
            supported = new ArrayList<>(context.getConfig().getSiteReport().getCipherSuites());
        }
        else {
            supported = new ArrayList<>(context.getConfig().getSiteReport().getSupportedTls13CipherSuites());
        }

        // supported only contains CipherSuites that are compatible with the keyExchange annotation
        supported.removeIf((CipherSuite i) -> !testMethodConfig.getKeyExchange().compatibleWithCiphersuite(i));


        if (!replaceSelectedCiphersuite) {
            if (stateModifier != null) {
                AnnotatedState ret = stateModifier.apply(annotatedState);
                if (ret != null)
                    annotatedState = ret;
            }
            List<AnnotatedState> ret = new ArrayList<>();
            ret.add(annotatedState);
            return ret;
        }

        for (CipherSuite i: supported) {
            Config config = state.getConfig().createCopy();

            if (replaceSelectedCiphersuite) {
                config.setDefaultServerSupportedCiphersuites(i);
                config.setDefaultSelectedCipherSuite(i);
            }

            WorkflowTrace trace;
            if (traceType != null) {
                config.setDefaultSelectedCipherSuite(i);
                trace = new WorkflowConfigurationFactory(config).createWorkflowTrace(traceType, RunningModeType.SERVER);
                if (this.untilHandshakeMessage != null)
                    WorkflowTraceMutator.truncateAt(trace, this.untilHandshakeMessage, this.untilSendingMessage);
                if (this.untilProtocolMessage != null)
                    WorkflowTraceMutator.truncateAt(trace, this.untilProtocolMessage, this.untilSendingMessage);
                WorkflowTrace tmpTrace = state.getWorkflowTraceCopy();
                trace.addTlsActions(tmpTrace.getTlsActions());
            }
            else {
                trace = state.getWorkflowTraceCopy();
            }

            AnnotatedState newState = new AnnotatedState(annotatedState, new State(config, trace));
            if (replaceSelectedCiphersuite) {
                newState.setInspectedCipherSuite(i);
            }

            if (stateModifier != null) {
                AnnotatedState ret = stateModifier.apply(newState);
                if (ret != null)
                    newState = ret;
            }

            result.add(newState);
        }

        return result;
    }


    private List<AnnotatedState> transformStateServerTest(AnnotatedState annotatedState) {
        List<AnnotatedState> result = new ArrayList<>();
        Config inputConfig = annotatedState.getState().getConfig();
        State state = annotatedState.getState();
        List<CipherSuite> supported;

        if (inputConfig.getHighestProtocolVersion() != ProtocolVersion.TLS13) {
            supported = new ArrayList<>(context.getConfig().getSiteReport().getCipherSuites());
        }
        else {
            supported = new ArrayList<>(context.getConfig().getSiteReport().getSupportedTls13CipherSuites());
        }

        // supported only contains CipherSuites that are compatible with the keyExchange annotation
        supported.removeIf((CipherSuite i) -> !testMethodConfig.getKeyExchange().compatibleWithCiphersuite(i));


        if (appendEachSupportedCiphersuiteToClientSupported && replaceSupportedCiphersuites) {
            throw new RuntimeException("appendEachSupportedCiphersuiteToSupported and replaceSupportedCiphersuites are mutually exclusive options.");
        }

        if (respectConfigSupportedCiphersuites) {
            List<CipherSuite> configCiphersuites = inputConfig.getDefaultClientSupportedCiphersuites();
            supported.removeIf(i -> !configCiphersuites.contains(i));
        }
        else if (appendEachSupportedCiphersuiteToClientSupported) {
            List<CipherSuite> configCiphersuites = inputConfig.getDefaultClientSupportedCiphersuites();
            supported.removeIf(configCiphersuites::contains);
        }

        if (!replaceSupportedCiphersuites && !appendEachSupportedCiphersuiteToClientSupported) {
            if (stateModifier != null) {
                AnnotatedState ret = stateModifier.apply(annotatedState);
                if (ret != null)
                    annotatedState = ret;
            }
            List<AnnotatedState> ret = new ArrayList<>();
            ret.add(annotatedState);
            return ret;
        }

        for (CipherSuite i: supported) {
            Config config = state.getConfig().createCopy();

            if (replaceSupportedCiphersuites) {
                config.setDefaultClientSupportedCiphersuites(i);
            }
            else if (appendEachSupportedCiphersuiteToClientSupported) {
                List<CipherSuite> ciphersuites = config.getDefaultClientSupportedCiphersuites();
                ciphersuites.add(i);
                config.setDefaultClientSupportedCiphersuites(ciphersuites);
            }

            WorkflowTrace trace;
            if (traceType != null) {
                config.setDefaultSelectedCipherSuite(i);
                trace = new WorkflowConfigurationFactory(config).createWorkflowTrace(traceType, RunningModeType.CLIENT);
                if (this.untilHandshakeMessage != null)
                    WorkflowTraceMutator.truncateAt(trace, this.untilHandshakeMessage, this.untilSendingMessage);
                if (this.untilProtocolMessage != null)
                    WorkflowTraceMutator.truncateAt(trace, this.untilProtocolMessage, this.untilSendingMessage);
                WorkflowTrace tmpTrace = state.getWorkflowTraceCopy();
                trace.addTlsActions(tmpTrace.getTlsActions());
            }
            else {
                trace = state.getWorkflowTraceCopy();
            }


            AnnotatedState newState = new AnnotatedState(annotatedState, new State(config, trace));
            if (replaceSupportedCiphersuites || appendEachSupportedCiphersuiteToClientSupported) {
                newState.setInspectedCipherSuite(i);
            }

            if (stateModifier != null) {
                AnnotatedState ret = stateModifier.apply(newState);
                if (ret != null)
                    newState = ret;
            }

            result.add(newState);
        }

        return result;
    }


    private List<AnnotatedState> transformState(AnnotatedState state) {
        if (this.context.getConfig().getTestEndpointMode() == TestEndpointType.CLIENT) {
            return this.transformStateClientTest(state);
        }

        return this.transformStateServerTest(state);
    }


    public ExtensionContext getExtensionContext() {
        return extensionContext;
    }

    public void setExtensionContext(ExtensionContext extensionContext) {
        this.extensionContext = extensionContext;
    }

    public TestMethodConfig getTestMethodConfig() {
        return testMethodConfig;
    }

    public void setTestMethodConfig(TestMethodConfig testMethodConfig) {
        this.testMethodConfig = testMethodConfig;
    }

    public Function<AnnotatedState, AnnotatedState> getStateModifier() {
        return stateModifier;
    }

    public void setStateModifier(Function<AnnotatedState, AnnotatedState> stateModifier) {
        this.stateModifier = stateModifier;
    }
}
