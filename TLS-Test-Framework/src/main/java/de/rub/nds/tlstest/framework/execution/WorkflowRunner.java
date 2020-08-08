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
import de.rub.nds.tlstest.framework.constants.TestEndpointType;
import de.rub.nds.tlstest.framework.utils.TestMethodConfig;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.extension.ExtensionContext;

import javax.annotation.Nonnull;
import java.util.ArrayList;
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
        container.setUniqueId(extensionContext.getUniqueId());
        container.setTestMethodConfig(testMethodConfig);

        List<AnnotatedState> toAdd = new ArrayList<>();

        if (container.getStates().size() == 0) {
            LOGGER.warn("AnnotatedStateContainer does not contain any state. No Handshake will be performed...");
        }

        for (AnnotatedState i : container.getStates()) {
            TlsAction lastAction = i.getState().getWorkflowTrace().getLastAction();
            if (lastAction instanceof ReceivingAction) {
                List<ProtocolMessageType> messages = ((ReceivingAction) lastAction).getGoingToReceiveProtocolMessageTypes();
                if (messages.size() > 0 && messages.get(messages.size() - 1).equals(ProtocolMessageType.ALERT)) {
                    i.getState().getConfig().setReceiveFinalSocketStateWithTimeout(true);
                }
            }

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

        container.addAll(toAdd);

        List<State> states = container.getStates().parallelStream().map(AnnotatedState::getState).collect(Collectors.toList());
        if (context.getConfig().getTestEndpointMode() == TestEndpointType.SERVER) {
            context.getStateExecutor().bulkExecuteStateTasks(states);
        } else {
            List<TlsTask> tasks = states.stream().map(i -> {
                StateExecutionServerTask task = new StateExecutionServerTask(i, context.getConfig().getTestClientDelegate().getServerSocket(), 2);
                task.setBeforeAcceptCallback(context.getConfig().getTestClientDelegate().getWakeupScript());
                return task;
            }).collect(Collectors.toList());
            context.getStateExecutor().bulkExecuteTasks(tasks);
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

    private AnnotatedState buildFinalState(AnnotatedState annotatedState, Config newConfig) {
        WorkflowTrace trace;
        State state = annotatedState.getState();
        if (traceType == null) {
            trace = state.getWorkflowTraceCopy();
        } else {
            RunningModeType runningMode = RunningModeType.CLIENT;
            if (context.getConfig().getTestEndpointMode() == TestEndpointType.CLIENT) {
                runningMode = RunningModeType.SERVER;
            }
            trace = new WorkflowConfigurationFactory(newConfig).createWorkflowTrace(traceType, runningMode);
            if (this.untilHandshakeMessage != null)
                WorkflowTraceMutator.truncateAt(trace, this.untilHandshakeMessage, this.untilSendingMessage);
            if (this.untilProtocolMessage != null)
                WorkflowTraceMutator.truncateAt(trace, this.untilProtocolMessage, this.untilSendingMessage);
            WorkflowTrace tmpTrace = state.getWorkflowTraceCopy();
            trace.addTlsActions(tmpTrace.getTlsActions());
        }

        AnnotatedState result = new AnnotatedState(annotatedState, new State(newConfig, trace));
        if (replaceSupportedCiphersuites || appendEachSupportedCiphersuiteToClientSupported || replaceSelectedCiphersuite) {
            result.setInspectedCipherSuite(newConfig.getDefaultSelectedCipherSuite());
        }

        if (stateModifier != null) {
            AnnotatedState ret = stateModifier.apply(result);
            if (ret != null)
                result = ret;

            result.getState().reset();
        }

        return result;
    }

    private List<AnnotatedState> transformStateClientTest(AnnotatedState annotatedState) {
        List<AnnotatedState> result = new ArrayList<AnnotatedState>(){};
        List<CipherSuite> supported = new ArrayList<>(context.getSiteReport().getCipherSuites());
        Config inputConfig = annotatedState.getState().getConfig();

        if (inputConfig.getHighestProtocolVersion() == ProtocolVersion.TLS13) {
            supported.addAll(context.getSiteReport().getSupportedTls13CipherSuites());
        }

        // supported only contains CipherSuites that are compatible with the keyExchange annotation
        supported.removeIf((CipherSuite i) -> !testMethodConfig.getKeyExchange().compatibleWithCiphersuite(i));

        if (respectConfigSupportedCiphersuites) {
            List<CipherSuite> configCiphersuites = inputConfig.getDefaultServerSupportedCiphersuites();
            supported.removeIf(i -> !configCiphersuites.contains(i));
        }

        if (!replaceSelectedCiphersuite) {
            return new ArrayList<AnnotatedState>(){{
                add(buildFinalState(annotatedState, inputConfig.createCopy()));
            }};
        }

        for (CipherSuite i: supported) {
            Config config = inputConfig.createCopy();

            if (replaceSelectedCiphersuite) {
                // always true
                config.setDefaultServerSupportedCiphersuites(i);
                config.setDefaultSelectedCipherSuite(i);
            }

            AnnotatedState newState = buildFinalState(annotatedState, config);
            result.add(newState);
        }

        return result;
    }


    private List<AnnotatedState> transformStateServerTest(AnnotatedState annotatedState) {
        List<AnnotatedState> result = new ArrayList<>();
        Config inputConfig = annotatedState.getState().getConfig();
        List<CipherSuite> supported = new ArrayList<>(context.getSiteReport().getCipherSuites());

        if (inputConfig.getHighestProtocolVersion() == ProtocolVersion.TLS13) {
            supported.addAll(context.getSiteReport().getSupportedTls13CipherSuites());
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
            return new ArrayList<AnnotatedState>(){{
                add(buildFinalState(annotatedState, inputConfig.createCopy()));
            }};
        }

        for (CipherSuite i: supported) {
            Config config = inputConfig.createCopy();
            config.setDefaultSelectedCipherSuite(i);

            if (replaceSupportedCiphersuites) {
                config.setDefaultClientSupportedCiphersuites(i);
            }
            else if (appendEachSupportedCiphersuiteToClientSupported) {
                List<CipherSuite> ciphersuites = config.getDefaultClientSupportedCiphersuites();
                ciphersuites.add(i);
                config.setDefaultClientSupportedCiphersuites(ciphersuites);
            }

            AnnotatedState newState = buildFinalState(annotatedState, config);
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
