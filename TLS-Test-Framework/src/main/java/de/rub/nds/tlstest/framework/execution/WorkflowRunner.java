/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.execution;

import de.rub.nds.anvilcore.constants.TestEndpointType;
import de.rub.nds.anvilcore.teststate.AnvilTestCase;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.NewSessionTicketMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceConfigurationUtil;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceMutator;
import de.rub.nds.tlsattacker.core.workflow.action.GenericReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceivingAction;
import de.rub.nds.tlsattacker.core.workflow.action.ResetConnectionAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import de.rub.nds.tlsattacker.core.workflow.action.executor.WorkflowExecutorType;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsattacker.core.workflow.task.StateExecutionTask;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import de.rub.nds.tlsattacker.transport.tcp.TcpTransportHandler;
import de.rub.nds.tlsattacker.transport.udp.ServerUdpTransportHandler;
import de.rub.nds.tlsattacker.transport.udp.UdpTransportHandler;
import de.rub.nds.tlstest.framework.ClientFeatureExtractionResult;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.anvil.TlsParameterCombination;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.extension.ExtensionContext;

/**
 * An object of this class is passed to every test method, it is created by the
 * WorkflowRunnerResolver class
 */
public class WorkflowRunner {
    private static final Logger LOGGER = LogManager.getLogger();

    private TestContext context = null;
    private ExtensionContext extensionContext = null;

    private Config preparedConfig;
    private State state;

    private TlsParameterCombination parameterCombination;
    private HandshakeMessageType untilHandshakeMessage;
    private ProtocolMessageType untilProtocolMessage;
    private Boolean untilSendingMessage = null;
    private Boolean untilLast = false;

    // adjust WorkflowTrace if necessary
    private Boolean autoHelloRetryRequest = true;
    private Boolean autoAdaptForDtls = true;

    private static Map<ExtensionContext, WorkflowRunner> workflowRunners = new HashMap<>();

    public WorkflowRunner(ExtensionContext extensionContext) {
        this.context = TestContext.getInstance();
        this.extensionContext = extensionContext;
        WorkflowRunner.workflowRunners.put(extensionContext, this);
    }

    public WorkflowRunner(ExtensionContext extensionContext, Config config) {
        this(extensionContext);
        this.preparedConfig = config;
    }

    /**
     * Executes a WorkflowTrace. It performs the derivation and executes each derived handshake.
     *
     * @param trace Trace to execute
     * @param config TLS-Attacker Config to be used for execution
     * @return
     */
    public State execute(WorkflowTrace trace, Config config) {
        // don't run if testRun is already aborted
        if (context.isAborted()) {
            state = new State();
            return state;
        }

        if (preparedConfig == null) {
            LOGGER.warn(
                    "Config was not set before execution - WorkflowTrace may be invalid for Test:"
                            + extensionContext.getRequiredTestMethod().getName());
            preparedConfig = config;
        }

        adaptWorkflowTrace(trace, config);
        state = new State(config, trace);
        StateExecutionTask task =
                new StateExecutionTask(state, context.getStateExecutor().getReexecutions());
        if (context.getConfig().getTestEndpointMode() == TestEndpointType.SERVER) {
            prepareServerTask(task);
        } else {
            prepareClientTask(task);
        }
        task.setAfterExecutionCallback(this::afterExecutionCallback);
        context.getStateExecutor().bulkExecuteTasks(task);
        postExecution();
        return state;
    }

    private Integer afterExecutionCallback(State state) {
        AnvilTestCase testCase = AnvilTestCase.fromExtensionContext(extensionContext);

        TransportHandler transportHandler = state.getTlsContext().getTransportHandler();
        if (transportHandler instanceof UdpTransportHandler) {
            UdpTransportHandler udpTransportHandler = (UdpTransportHandler) transportHandler;
            testCase.setDstPort(udpTransportHandler.getDstPort());
            testCase.setSrcPort(udpTransportHandler.getSrcPort());
        } else {
            testCase.setDstPort(((TcpTransportHandler) transportHandler).getDstPort());
            testCase.setSrcPort(((TcpTransportHandler) transportHandler).getSrcPort());
        }
        if (transportHandler instanceof UdpTransportHandler) {
            try {
                transportHandler.closeConnection();
            } catch (Exception ignored) {
            }
        }

        testCase.setStartTime(new Date(state.getStartTimestamp()));
        testCase.setEndTime(new Date(state.getEndTimestamp()));

        Integer relevantPort =
                state.getContext().getConfig().getDefaultRunningMode() == RunningModeType.CLIENT
                        ? testCase.getSrcPort()
                        : testCase.getDstPort();
        if (relevantPort != null && relevantPort != -1) {
            testCase.setCaseSpecificPcapFilter(String.format("port %d", relevantPort));
        } else {
            LOGGER.warn(
                    "Encountered invalid port for packet filter in test {} with combination {}: {}",
                    testCase.getAssociatedContainer().getName(),
                    testCase.getDisplayName(),
                    (relevantPort != null) ? "Port is -1" : "Port is null");
        }

        if (state.getTlsContext().isReceivedTransportHandlerException()) {
            testCase.addAdditionalResultInfo("Received TransportHandler exception");
        }

        return 0;
    }

    public void postExecution() {
        AnvilTestCase testCase = AnvilTestCase.fromExtensionContext(extensionContext);

        // fallback to extract ports if WorkflowExecutor did not apply callback
        if (testCase.getSrcPort() == null && testCase.getDstPort() == null) {
            try {
                afterExecutionCallback(state);
            } catch (Exception ignored) {
            }
        }
    }

    public void adaptWorkflowTrace(WorkflowTrace trace, Config config) {
        if (config.getWorkflowExecutorType() == WorkflowExecutorType.DTLS) {
            config.setWorkflowExecutorShouldClose(false);
        }

        if (shouldAdaptForDtls(trace, config)) {
            adaptForDtls(trace, config, context.getConfig().getTestEndpointMode());
        }

        if (shouldInsertHelloRetryRequest()) {
            insertHelloRetryRequest(trace, config.getDefaultSelectedNamedGroup());
        }

        if (shouldInsertNewSessionTicket()) {
            insertTls12NewSessionTicket(trace);
        }

        if (preparedConfig.getHighestProtocolVersion() == ProtocolVersion.TLS13
                && context.getConfig().getTestEndpointMode() == TestEndpointType.SERVER) {
            allowOptionalTls13NewSessionTickets(trace);
        } else if (preparedConfig.getHighestProtocolVersion() == ProtocolVersion.TLS13
                && context.getConfig().getTestEndpointMode() == TestEndpointType.CLIENT) {
            allowOptionalClientCcs(trace);
        }

        allowOptionalClientApplicationMessage(trace);
    }

    public void prepareServerTask(StateExecutionTask task) {
        TestContext.getInstance().increaseServerHandshakesSinceRestart();
        if (TestContext.getInstance().getServerHandshakesSinceRestart()
                        == TestContext.getInstance()
                                .getConfig()
                                .getAnvilTestConfig()
                                .getRestartServerAfter()
                && TestContext.getInstance().getConfig().getTimeoutActionScript() != null) {
            LOGGER.info("Scheduling server restart with task");
            task.setBeforeTransportPreInitCallback(
                    (State state) -> {
                        try {
                            return TestContext.getInstance()
                                    .getConfig()
                                    .getTimeoutActionScript()
                                    .call();
                        } catch (Exception ex) {
                            LOGGER.error(ex);
                            return 1;
                        }
                    });
            TestContext.getInstance().resetServerHandshakesSinceRestart();
        }
    }

    public void prepareClientTask(StateExecutionTask task) throws RuntimeException {
        if (context.getConfig().isUseDTLS()) {
            // TODO: Close UDP socket if still open before reexecution
            // task.setBeforeReexecutionCallback(this::reexecutionCallback);
        }
    }

    /**
     * For UDP, WorkflowExecutionExceptions may cause the DatagramSocket to remain unclosed. Since
     * we can not bind to the same port upon reexecution, we set a callback to close the socket if
     * it is still open.
     */
    private Integer reexecutionCallback(State state) {
        ServerUdpTransportHandler udpTransportHandler =
                (ServerUdpTransportHandler) state.getTlsContext().getTransportHandler();
        try {
            if (udpTransportHandler.isInitialized() && !udpTransportHandler.isClosed()) {
                udpTransportHandler.closeConnection();
            }
        } catch (IOException ex) {
            LOGGER.error(ex);
            return 1;
        }
        return 0;
    }

    /**
     * Configures the WorkflowRunner to use the WorkflowConfigurationFactory to generate workflow
     * traces. The workflows are generated when the buildFinalState is called. This function is
     * called when the derivation is executed.
     *
     * @param type WorkflowTraceType that should be used for the generated workflowTrace
     * @return empty WorkflowTrace
     */
    public WorkflowTrace generateWorkflowTrace(WorkflowTraceType type) {
        RunningModeType runningMode = resolveRunningMode(context.getConfig().getTestEndpointMode());
        WorkflowTrace trace =
                new WorkflowConfigurationFactory(preparedConfig)
                        .createWorkflowTrace(type, runningMode);
        if (this.untilHandshakeMessage != null)
            WorkflowTraceMutator.truncateAt(
                    trace, this.untilHandshakeMessage, this.untilSendingMessage, untilLast);
        if (this.untilProtocolMessage != null)
            WorkflowTraceMutator.truncateAt(
                    trace, this.untilProtocolMessage, this.untilSendingMessage, untilLast);
        return trace;
    }

    public WorkflowTrace generateWorkflowTraceUntilMessage(
            WorkflowTraceType type, HandshakeMessageType handshakeMessageType) {
        this.untilHandshakeMessage = handshakeMessageType;
        this.untilProtocolMessage = null;

        return generateWorkflowTrace(type);
    }

    public WorkflowTrace generateWorkflowTraceUntilMessage(
            WorkflowTraceType type, ProtocolMessageType protocolMessageType) {
        this.untilHandshakeMessage = null;
        this.untilProtocolMessage = protocolMessageType;

        return generateWorkflowTrace(type);
    }

    public WorkflowTrace generateWorkflowTraceUntilSendingMessage(
            WorkflowTraceType type, HandshakeMessageType handshakeMessageType) {
        this.untilHandshakeMessage = handshakeMessageType;
        this.untilProtocolMessage = null;
        this.untilSendingMessage = true;

        return generateWorkflowTrace(type);
    }

    public WorkflowTrace generateWorkflowTraceUntilSendingMessage(
            WorkflowTraceType type, ProtocolMessageType protocolMessageType) {
        this.untilHandshakeMessage = null;
        this.untilProtocolMessage = protocolMessageType;
        this.untilSendingMessage = true;

        return generateWorkflowTrace(type);
    }

    public WorkflowTrace generateWorkflowTraceUntilReceivingMessage(
            WorkflowTraceType type, HandshakeMessageType handshakeMessageType) {
        this.untilHandshakeMessage = handshakeMessageType;
        this.untilProtocolMessage = null;
        this.untilSendingMessage = false;

        return generateWorkflowTrace(type);
    }

    public WorkflowTrace generateWorkflowTraceUntilReceivingMessage(
            WorkflowTraceType type, ProtocolMessageType protocolMessageType) {
        this.untilHandshakeMessage = null;
        this.untilProtocolMessage = protocolMessageType;
        this.untilSendingMessage = false;

        return generateWorkflowTrace(type);
    }

    public WorkflowTrace generateWorkflowTraceUntilLastMessage(
            WorkflowTraceType type, HandshakeMessageType handshakeMessageType) {
        this.untilHandshakeMessage = handshakeMessageType;
        this.untilProtocolMessage = null;
        this.untilLast = true;

        return generateWorkflowTrace(type);
    }

    public WorkflowTrace generateWorkflowTraceUntilLastMessage(
            WorkflowTraceType type, ProtocolMessageType protocolMessageType) {
        this.untilHandshakeMessage = null;
        this.untilProtocolMessage = protocolMessageType;
        this.untilLast = true;

        return generateWorkflowTrace(type);
    }

    public WorkflowTrace generateWorkflowTraceUntilLastSendingMessage(
            WorkflowTraceType type, HandshakeMessageType handshakeMessageType) {
        this.untilHandshakeMessage = handshakeMessageType;
        this.untilProtocolMessage = null;
        this.untilSendingMessage = true;
        this.untilLast = true;

        return generateWorkflowTrace(type);
    }

    public WorkflowTrace generateWorkflowTraceUntilLastSendingMessage(
            WorkflowTraceType type, ProtocolMessageType protocolMessageType) {
        this.untilHandshakeMessage = null;
        this.untilProtocolMessage = protocolMessageType;
        this.untilSendingMessage = true;
        this.untilLast = true;

        return generateWorkflowTrace(type);
    }

    public WorkflowTrace generateWorkflowTraceUntilLastReceivingMessage(
            WorkflowTraceType type, HandshakeMessageType handshakeMessageType) {
        this.untilHandshakeMessage = handshakeMessageType;
        this.untilProtocolMessage = null;
        this.untilSendingMessage = false;
        this.untilLast = true;

        return generateWorkflowTrace(type);
    }

    public WorkflowTrace generateWorkflowTraceUntilLastReceivingMessage(
            WorkflowTraceType type, ProtocolMessageType protocolMessageType) {
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

    public TlsParameterCombination getTlsParameterCombination() {
        return parameterCombination;
    }

    public void setTlsParameterCombination(TlsParameterCombination derivationContainer) {
        this.parameterCombination = derivationContainer;
    }

    public boolean shouldInsertHelloRetryRequest() {
        if (!autoHelloRetryRequest
                || context.getConfig().getTestEndpointMode() == TestEndpointType.SERVER
                || preparedConfig.getHighestProtocolVersion() != ProtocolVersion.TLS13
                || !context.getFeatureExtractionResult()
                        .getNamedGroups()
                        .contains(preparedConfig.getDefaultSelectedNamedGroup())
                || ((ClientFeatureExtractionResult) context.getFeatureExtractionResult())
                        .getClientHelloKeyShareGroups()
                        .contains(preparedConfig.getDefaultSelectedNamedGroup())) {
            return false;
        }
        return true;
    }

    private static RunningModeType resolveRunningMode(TestEndpointType testEndpointType) {
        RunningModeType runningMode = RunningModeType.CLIENT;
        if (testEndpointType == TestEndpointType.CLIENT) {
            runningMode = RunningModeType.SERVER;
        }
        return runningMode;
    }

    public static void adaptForDtls(
            WorkflowTrace trace, Config config, TestEndpointType testEndpointType) {
        WorkflowConfigurationFactory workflowFactory = new WorkflowConfigurationFactory(config);
        RunningModeType runningModeType = resolveRunningMode(testEndpointType);
        WorkflowTrace completeHandshake =
                workflowFactory.createWorkflowTrace(WorkflowTraceType.HANDSHAKE, runningModeType);
        List<ProtocolMessage> plannedMessages =
                WorkflowTraceConfigurationUtil.getAllStaticConfiguredSendMessages(trace);
        ProtocolMessage lastMessage = plannedMessages.get(plannedMessages.size() - 1);
        if (lastMessage.getProtocolMessageType() == ProtocolMessageType.HANDSHAKE) {
            HandshakeMessage lastHandshakeMessage = (HandshakeMessage) lastMessage;
            SendAction lastSendAction =
                    (SendAction)
                            WorkflowTraceConfigurationUtil.getLastStaticConfiguredSendAction(
                                    trace, lastHandshakeMessage.getHandshakeMessageType());
            SendAction fullHandshakeEquivalentAction =
                    (SendAction)
                            WorkflowTraceConfigurationUtil.getFirstStaticConfiguredSendAction(
                                    completeHandshake,
                                    lastHandshakeMessage.getHandshakeMessageType());
            completeMessageFlight(
                    fullHandshakeEquivalentAction, completeHandshake, lastSendAction, lastMessage);
        } else if (lastMessage.getProtocolMessageType() == ProtocolMessageType.CHANGE_CIPHER_SPEC) {
            SendAction lastSendAction =
                    (SendAction)
                            WorkflowTraceConfigurationUtil.getLastStaticConfiguredSendAction(
                                    trace, ProtocolMessageType.CHANGE_CIPHER_SPEC);
            SendAction fullHandshakeEquivalentAction =
                    (SendAction)
                            WorkflowTraceConfigurationUtil.getLastStaticConfiguredSendAction(
                                    completeHandshake, ProtocolMessageType.CHANGE_CIPHER_SPEC);
            completeMessageFlight(
                    fullHandshakeEquivalentAction, completeHandshake, lastSendAction, lastMessage);
        } else {
            // this trace either manipulates a non-handshake message or places the message
            // outside of a valid flow
            // adding handshake message to the invalid flow would appear to be
            // a valid handshake flow for the receiver as the message SQNs
            // remain valid
            throw new IllegalArgumentException(
                    "Unable to adapt trace for DTLS as last planned message is not part of a regular handshake");
        }
    }

    private static void completeMessageFlight(
            SendAction fullHandshakeEquivalentAction,
            WorkflowTrace completeHandshake,
            SendAction firstSendAction,
            ProtocolMessage lastHandshakeMessage)
            throws IllegalArgumentException {
        if (fullHandshakeEquivalentAction != null) {
            int fullHandshakeEquivalentActionIndex =
                    completeHandshake.getTlsActions().indexOf(fullHandshakeEquivalentAction);
            // add subsequent messages from the equivalent send action
            firstSendAction
                    .getConfiguredMessages()
                    .addAll(
                            fullHandshakeEquivalentAction
                                    .getConfiguredMessages()
                                    .subList(
                                            fullHandshakeEquivalentAction
                                                            .getConfiguredMessages()
                                                            .indexOf(lastHandshakeMessage)
                                                    + 1,
                                            fullHandshakeEquivalentAction
                                                    .getConfiguredMessages()
                                                    .size()));
            // also add message from all send actions that are immediately after another send action
            // (only applies when we spilt into multiple send actions)
            for (int i = fullHandshakeEquivalentActionIndex + 1;
                    i < completeHandshake.getTlsActions().size();
                    i++) {
                if (completeHandshake.getTlsActions().get(i) instanceof SendAction) {
                    firstSendAction
                            .getConfiguredMessages()
                            .addAll(
                                    ((SendAction) completeHandshake.getTlsActions().get(i))
                                            .getConfiguredMessages());
                } else {
                    break;
                }
            }
        } else {
            throw new IllegalArgumentException(
                    "Unable to adapt trace for DTLS as last message is not included in benign handshake");
        }
    }

    /**
     * Since DTLS does not use TCP, we can not leverage the connection state. Hence, to identify if
     * a peer detected a manipulated message within a flight of our messages, we must always
     * conclude the flight. The peer should then either proceed with the handshake, which means the
     * manipulation remained unnoticed, or remain within the current state (with no messages sent /
     * alert / retransmission).
     *
     * @param trace The WorkflowTrace built by the test
     * @param config The Config prepared by the
     * @return true if the WorklfowTrace should be adapted to enable evaluation
     */
    private boolean shouldAdaptForDtls(WorkflowTrace trace, Config config) {
        if (isAutoAdaptForDtls() && config.getHighestProtocolVersion().isDTLS()) {
            TlsAction lastAction = trace.getTlsActions().get(trace.getTlsActions().size() - 1);
            boolean lastActionIsGenericReceive = lastAction instanceof GenericReceiveAction;
            boolean isExpectingAlert = false;
            if (!lastActionIsGenericReceive) {
                isExpectingAlert =
                        lastAction instanceof ReceivingAction
                                && ((ReceiveAction) lastAction)
                                        .getExpectedMessages().stream()
                                                .anyMatch(
                                                        message ->
                                                                message.getProtocolMessageType()
                                                                        == ProtocolMessageType
                                                                                .ALERT);
            }

            // we never have to add anything if we do not even send a CH
            return WorkflowTraceConfigurationUtil.getLastStaticConfiguredSendMessage(
                                    trace, HandshakeMessageType.CLIENT_HELLO)
                            != null
                    && (lastActionIsGenericReceive || isExpectingAlert);
        }
        return false;
    }

    private boolean shouldInsertNewSessionTicket() {
        if (context.getConfig().getTestEndpointMode() == TestEndpointType.SERVER
                && preparedConfig.getHighestProtocolVersion() == ProtocolVersion.TLS12
                && preparedConfig.isAddSessionTicketTLSExtension()) {
            return true;
        }
        return false;
    }

    public void insertTls12NewSessionTicket(WorkflowTrace trace) {
        ReceiveAction receiveChangeCipherSpec =
                (ReceiveAction)
                        WorkflowTraceConfigurationUtil.getFirstStaticConfiguredReceiveAction(
                                trace, ProtocolMessageType.CHANGE_CIPHER_SPEC);

        // not all WorkflowTraces reach a ChangeCipherSpec
        if (receiveChangeCipherSpec != null) {
            NewSessionTicketMessage newSessionTicket = new NewSessionTicketMessage();
            newSessionTicket.setRequired(false);
            receiveChangeCipherSpec.getExpectedMessages().add(0, newSessionTicket);
        }
    }

    public void insertHelloRetryRequest(WorkflowTrace trace, NamedGroup requestedGroup) {
        ClientHelloMessage failingClientHello = new ClientHelloMessage();
        ServerHelloMessage helloRetryRequest = new ServerHelloMessage(preparedConfig);
        helloRetryRequest.setRandom(
                Modifiable.explicit(ServerHelloMessage.getHelloRetryRequestRandom()));

        if (requestedGroup != preparedConfig.getDefaultSelectedNamedGroup()
                && helloRetryRequest.containsExtension(ExtensionType.KEY_SHARE)) {
            KeyShareExtensionMessage keyShareExtension =
                    helloRetryRequest.getExtension(KeyShareExtensionMessage.class);
            keyShareExtension.setKeyShareListBytes(Modifiable.explicit(requestedGroup.getValue()));
        }

        trace.getTlsActions().add(0, new SendAction(helloRetryRequest));
        trace.getTlsActions().add(0, new ReceiveAction(failingClientHello));

        ChangeCipherSpecMessage compatibilityCCS = new ChangeCipherSpecMessage();
        compatibilityCCS.setRequired(false);
        // OpenSSL sends  ChangeCipherSpec || ClientHello upon HelloRetry
        ((ReceiveAction) trace.getTlsActions().get(2))
                .getExpectedMessages()
                .add(0, compatibilityCCS);
    }

    public void allowOptionalTls13NewSessionTickets(WorkflowTrace trace) {
        boolean mayReceiveNewSessionTicketFromNow = false;
        for (TlsAction action : trace.getTlsActions()) {
            if (action instanceof ReceiveAction) {
                ReceiveAction receiveAction = (ReceiveAction) action;
                if (receiveAction.getExpectedMessages() != null) {
                    if (receiveAction.getExpectedMessages().stream()
                            .anyMatch(message -> message instanceof FinishedMessage)) {
                        mayReceiveNewSessionTicketFromNow = true;
                    }
                    // set explicitly expected new session tickets as optional to
                    // allow early NewSessionTickets sent with Fin
                    receiveAction.getExpectedMessages().stream()
                            .filter(message -> message instanceof NewSessionTicketMessage)
                            .forEach(newSessionTicket -> newSessionTicket.setRequired(false));
                }
                if (mayReceiveNewSessionTicketFromNow) {
                    receiveAction.addActionOption(
                            ActionOption.IGNORE_UNEXPECTED_NEW_SESSION_TICKETS);
                }
            } else if (action instanceof ResetConnectionAction) {
                mayReceiveNewSessionTicketFromNow = false;
            }
        }
    }

    public void allowOptionalClientCcs(WorkflowTrace trace) {
        boolean ccsAlreadyExpected = false;
        for (ReceivingAction receiving : trace.getReceivingActions()) {
            if (receiving instanceof ReceiveAction) {
                ReceiveAction receiveAction = (ReceiveAction) receiving;
                if (receiveAction.getExpectedMessages().stream()
                        .anyMatch(
                                message ->
                                        message.getProtocolMessageType()
                                                == ProtocolMessageType.CHANGE_CIPHER_SPEC)) {
                    ccsAlreadyExpected = true;
                }
            }
        }

        // this will only affect alerts expected during the handshake as we allways
        // add an optional css beforehand otherwise
        if (trace.getLastReceivingAction() != null
                && trace.getLastReceivingAction() instanceof ReceiveAction
                && !ccsAlreadyExpected
                && ((ReceiveAction) trace.getLastReceivingAction())
                        .getExpectedMessages().stream()
                                .anyMatch(
                                        message ->
                                                message.getProtocolMessageType()
                                                        == ProtocolMessageType.ALERT)) {
            ReceiveAction lastReceive = (ReceiveAction) trace.getLastReceivingAction();
            ChangeCipherSpecMessage optionalCcs = new ChangeCipherSpecMessage();
            optionalCcs.setRequired(false);
            lastReceive.getExpectedMessages().add(0, optionalCcs);
        }
    }

    public void allowOptionalClientApplicationMessage(WorkflowTrace trace) {
        if (context.getConfig().getTestEndpointMode() == TestEndpointType.CLIENT) {
            boolean mayReceiveApplicationDataFromNow = false;
            for (TlsAction action : trace.getTlsActions()) {
                if (action instanceof ReceiveAction) {
                    ReceiveAction receiveAction = (ReceiveAction) action;
                    if (receiveAction.getExpectedMessages().stream()
                                    .anyMatch(message -> message instanceof FinishedMessage)
                            && preparedConfig.getHighestProtocolVersion()
                                    == ProtocolVersion.TLS13) {
                        mayReceiveApplicationDataFromNow = true;

                        // only allow *after* Finished
                        ApplicationMessage optionalAppMsg = new ApplicationMessage();
                        optionalAppMsg.setRequired(false);
                        receiveAction.getExpectedMessages().add(optionalAppMsg);
                    } else {
                        if (mayReceiveApplicationDataFromNow) {
                            ApplicationMessage optionalAppMsg = new ApplicationMessage();
                            optionalAppMsg.setRequired(false);
                            receiveAction.getExpectedMessages().add(0, optionalAppMsg);
                        }
                    }

                } else if (action instanceof ResetConnectionAction) {
                    mayReceiveApplicationDataFromNow = false;
                } else if (action instanceof SendAction
                        && preparedConfig.getHighestProtocolVersion() != ProtocolVersion.TLS13) {
                    SendAction sendAction = (SendAction) action;
                    if (sendAction.getSentMessages().stream()
                            .anyMatch(message -> message instanceof FinishedMessage)) {
                        mayReceiveApplicationDataFromNow = true;
                    }
                }
            }
        }
    }

    public Boolean isAutoHelloRetryRequest() {
        return autoHelloRetryRequest;
    }

    public void setAutoHelloRetryRequest(Boolean autoHelloRetryRequest) {
        this.autoHelloRetryRequest = autoHelloRetryRequest;
    }

    public Boolean isAutoAdaptForDtls() {
        return autoAdaptForDtls;
    }

    public void setAutoAdaptForDtls(Boolean autoAdaptForDtls) {
        this.autoAdaptForDtls = autoAdaptForDtls;
    }
}
