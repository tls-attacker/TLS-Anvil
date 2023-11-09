package de.rub.nds.tlstest.framework.execution;

import de.rub.nds.anvilcore.constants.TestEndpointType;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.SendingAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Stream;
import org.junit.Assert;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class WorkflowRunnerTest {

    private static Config sharedConfig;
    private static WorkflowConfigurationFactory workflowFactory;

    public WorkflowRunnerTest() {}

    @BeforeAll
    private static void setupClass() {
        sharedConfig = new Config();
        sharedConfig.setDefaultSelectedCipherSuite(
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256);
        sharedConfig.setDefaultSelectedNamedGroup(NamedGroup.SECP256R1);
        workflowFactory = new WorkflowConfigurationFactory(sharedConfig);
    }

    @ParameterizedTest
    @MethodSource("provideNothingToDoWorkflowTraces")
    public void testAdaptForDtlsNothingToDo(
            WorkflowTrace trace, Config config, TestEndpointType runningModeType) {
        WorkflowTrace initialTrace = WorkflowTrace.copy(trace);
        WorkflowRunner.adaptForDtls(trace, config, runningModeType);
        Assert.assertEquals(initialTrace, trace);
    }

    @ParameterizedTest
    @MethodSource("provideIncompleteFlightWorkflowTraces")
    public void testAdaptForDtls(
            WorkflowTrace trace,
            Config config,
            TestEndpointType runningModeType,
            List<ProtocolMessage> messageToBeAdded) {
        WorkflowTrace initialTrace = WorkflowTrace.copy(trace);
        WorkflowRunner.adaptForDtls(trace, config, runningModeType);
        List<ProtocolMessage> addedMessages =
                removeTrailingFlightMessages(trace, messageToBeAdded.size());
        // ensure only expected messages have been added
        Assert.assertEquals(messageToBeAdded, addedMessages);
        // ensure WorkflowTrace is identical when added messages have been removed again
        Assert.assertEquals(initialTrace, trace);
    }

    public static Stream<Arguments> provideIncompleteFlightWorkflowTraces() {

        List<Arguments> testArguments = new LinkedList<>();
        WorkflowTrace helloServerTrace =
                workflowFactory.createWorkflowTrace(
                        WorkflowTraceType.HELLO, RunningModeType.SERVER);
        getTestInputsForAction(helloServerTrace, TestEndpointType.CLIENT, testArguments);

        WorkflowTrace clientFinTrace =
                workflowFactory.createWorkflowTrace(
                        WorkflowTraceType.HANDSHAKE, RunningModeType.CLIENT);
        getTestInputsForAction(clientFinTrace, TestEndpointType.SERVER, testArguments);
        return testArguments.stream();
    }

    private static void getTestInputsForAction(
            WorkflowTrace workflowTrace,
            TestEndpointType endpointType,
            List<Arguments> testArguments) {
        SendingAction messageFlight =
                workflowTrace.getSendingActions().get(workflowTrace.getSendingActions().size() - 1);
        for (int i = 1; i < messageFlight.getSendMessages().size(); i++) {
            WorkflowTrace modifiedTrace = WorkflowTrace.copy(workflowTrace);
            List<ProtocolMessage> removedMessages = removeTrailingFlightMessages(modifiedTrace, i);
            testArguments.add(
                    Arguments.of(modifiedTrace, sharedConfig, endpointType, removedMessages));
        }
    }

    public static Stream<Arguments> provideNothingToDoWorkflowTraces() {
        WorkflowTrace firstMessageSkippedIntentionally =
                workflowFactory.createWorkflowTrace(
                        WorkflowTraceType.HANDSHAKE, RunningModeType.SERVER);
        firstMessageSkippedIntentionally
                .getSendingActions()
                .get(firstMessageSkippedIntentionally.getSendingActions().size() - 1)
                .getSendMessages()
                .remove(0);
        WorkflowTrace secondMessageSkippedIntentionally =
                workflowFactory.createWorkflowTrace(
                        WorkflowTraceType.HANDSHAKE, RunningModeType.SERVER);
        secondMessageSkippedIntentionally
                .getSendingActions()
                .get(secondMessageSkippedIntentionally.getSendingActions().size() - 1)
                .getSendMessages()
                .remove(0);

        return Stream.of(
                Arguments.of(
                        workflowFactory.createWorkflowTrace(
                                WorkflowTraceType.HELLO, RunningModeType.CLIENT),
                        sharedConfig,
                        TestEndpointType.SERVER),
                Arguments.of(
                        workflowFactory.createWorkflowTrace(
                                WorkflowTraceType.HANDSHAKE, RunningModeType.CLIENT),
                        sharedConfig,
                        TestEndpointType.SERVER),
                Arguments.of(
                        workflowFactory.createWorkflowTrace(
                                WorkflowTraceType.FULL_RESUMPTION, RunningModeType.CLIENT),
                        sharedConfig,
                        TestEndpointType.SERVER),
                Arguments.of(
                        firstMessageSkippedIntentionally, sharedConfig, TestEndpointType.CLIENT),
                Arguments.of(
                        secondMessageSkippedIntentionally, sharedConfig, TestEndpointType.CLIENT));
    }

    private static List<ProtocolMessage> removeTrailingFlightMessages(
            WorkflowTrace modifiedTrace, int messagesToRemove) {
        List<ProtocolMessage> baseList =
                modifiedTrace
                        .getSendingActions()
                        .get(modifiedTrace.getSendingActions().size() - 1)
                        .getSendMessages();
        List<ProtocolMessage> removedMessages = new LinkedList<>();
        for (int i = 0; i < messagesToRemove; i++) {
            removedMessages.add(baseList.remove(baseList.size() - 1));
        }
        return removedMessages;
    }
}
