/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework;

import static org.junit.Assert.*;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.constants.TestEndpointType;
import de.rub.nds.anvilcore.teststate.AnvilTestCase;
import de.rub.nds.anvilcore.teststate.TestResult;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.Tls13KeySetType;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.UnknownMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipher;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipherFactory;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySet;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySetGenerator;
import de.rub.nds.tlsattacker.core.record.crypto.RecordDecryptor;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.GenericReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.MessageAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceivingAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendingAction;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;
import de.rub.nds.tlsattacker.transport.socket.SocketState;
import de.rub.nds.tlstest.framework.constants.AssertMsgs;
import de.rub.nds.tlstest.framework.model.derivationParameter.TcpFragmentationDerivation;
import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class Validator {
    private static final Logger LOGGER = LogManager.getLogger();

    public static boolean socketClosed(SocketState socketState) {
        return (socketState == SocketState.SOCKET_EXCEPTION
                || socketState == SocketState.CLOSED
                || socketState == SocketState.IO_EXCEPTION);
    }

    public static boolean socketClosed(State state) {
        SocketState socketState = getSocketState(state);
        return socketClosed(socketState);
    }

    public static void receivedFatalAlert(State state, AnvilTestCase testCase, boolean checkExecutedAsPlanned) {
        WorkflowTrace trace = state.getWorkflowTrace();
        SocketState socketState = getSocketState(state);
        boolean lastActionFailed = false;
        if (checkExecutedAsPlanned) {
            try {
                smartExecutedAsPlanned(state, testCase);
            } catch (Throwable e) {
                if (traceFailedBeforeAlertAction(trace)) {
                    testCase.addAdditionalResultInfo(AssertMsgs.WORKFLOW_NOT_EXECUTED_BEFORE_ALERT);
                    throw e;
                }
                lastActionFailed = true;
            }
        }

        AlertMessage lastAlert = trace.getLastReceivedMessage(AlertMessage.class);
        List<ProtocolMessage> lastMessagesReceived = getMessagesOfLastReceive(state);
        String messageString =
                lastMessagesReceived.stream()
                        .map(ProtocolMessage::toCompactString)
                        .collect(Collectors.joining(","));
        boolean socketClosed = socketClosed(state);
        boolean receivedAlert = (lastAlert != null);
        boolean alertIsFatal = false;
        if (receivedAlert) {
            checkReceivedMultipleAlerts(testCase, trace);
            alertIsFatal = (lastAlert.getLevel().getValue() == AlertLevel.FATAL.getValue());
        }
        if (TestContext.getInstance().getConfig().isUseDTLS()) return;
        if (!socketClosed) {
            // must fail
            assertFalse("Socket still open after fatal alert", receivedAlert && alertIsFatal);
            assertFalse(
                    "Socket still open and only sent warning alert",
                    receivedAlert && !alertIsFatal);
            assertFalse(
                    "Expected a fatal alert but no messages have been received and socket is still open",
                    lastMessagesReceived.isEmpty());

            fail(
                    "Expected a fatal alert but received "
                            + messageString
                            + " and socket is still open.");
        } else {
            assertFalse(
                    "Socket was closed but unexpected messages have been received. Received: "
                            + messageString,
                    lastActionFailed && !lastMessagesReceived.isEmpty());

            if (!receivedAlert) {
                if (mayOmitDueToTls13(state)) {
                    testCase.addAdditionalResultInfo("SUT chose not to send an alert in TLS 1.3");
                } else {
                    testCase.addAdditionalResultInfo("Only socket closed (" + socketState + ")");
                    testCase.setTestResult(TestResult.CONCEPTUALLY_SUCCEEDED);
                }
            } else if (!alertIsFatal) {
                AlertDescription alertDescription =
                        AlertDescription.getAlertDescription(lastAlert.getDescription().getValue());
                testCase.addAdditionalResultInfo("Closed with warning alert (" + alertDescription + ")");
                if (alertDescription == AlertDescription.CLOSE_NOTIFY) {
                    // close notify is the only warning alert that is expected to terminate
                    // connections
                    testCase.setTestResult(TestResult.CONCEPTUALLY_SUCCEEDED);
                } else {
                    testCase.setTestResult(TestResult.FULLY_FAILED);
                }
            }
        }
    }

    private static boolean mayOmitDueToTls13(State state) {
        return state.getConfig().getHighestProtocolVersion()
                        == ProtocolVersion.TLS13
                && !TestContext.getInstance().getConfig().isExpectTls13Alerts();
    }

    private static SocketState getSocketState(State state) {
        SocketState socketState = state.getTcpContext().getFinalSocketState();
        return socketState;
    }

    public static List<ProtocolMessage> getMessagesOfLastReceive(State state) {
        List<ProtocolMessage> messagesReceived = new LinkedList<>();
        WorkflowTrace trace = state.getWorkflowTrace();
        ReceivingAction lastReceive = trace.getLastReceivingAction();
        if (lastReceive == null) {
            throw new RuntimeException(
                    "Test checks for alert but no receive action was listed in WorkflowTrace");
        } else {
            ReceivingAction alertReceivingAction =
                    (ReceivingAction)
                            WorkflowTraceUtil.getFirstReceivingActionForMessage(
                                    ProtocolMessageType.ALERT, trace);
            ReceivingAction receiveToExtractFrom;
            if (alertReceivingAction != null && lastReceive != alertReceivingAction) {
                throw new RuntimeException(
                        "Found receive action expecting an alert before final receive action");
            } else {
                receiveToExtractFrom = lastReceive;
            }

            if (((MessageAction) receiveToExtractFrom).isExecuted()) {
                messagesReceived.addAll(receiveToExtractFrom.getReceivedMessages());
            }

            return messagesReceived;
        }
    }

    public static void checkReceivedMultipleAlerts(AnvilTestCase testCase, WorkflowTrace trace) {
        List<ProtocolMessage> receivedAlerts =
                WorkflowTraceUtil.getAllReceivedMessages(trace, ProtocolMessageType.ALERT);
        if (receivedAlerts.size() > 1) {
            testCase.addAdditionalResultInfo(
                    "Received multiple Alerts while waiting for Fatal Alert ("
                            + receivedAlerts.stream()
                                    .map(alert -> ((ProtocolMessage) alert).toCompactString())
                                    .collect(Collectors.joining(","))
                            + ")");
        }
    }

    public static void checkForUnknownMessage(State state, AnvilTestCase testCase) {
        if (state.getWorkflowTrace().getFirstReceivedMessage(UnknownMessage.class) != null) {
            testCase.addAdditionalResultInfo("Found unknown message");
        } else if (WorkflowTraceUtil.hasUnreadBytes(state.getWorkflowTrace())) {
            testCase.addAdditionalResultInfo("Found unread bytes in layer, this may be a parsing error");
        }
    }

    public static void receivedFatalAlert(State state, AnvilTestCase testCase) {
        receivedFatalAlert(state, testCase, true);
    }

    public static void executedAsPlanned(State state, AnvilTestCase testCase) {
        checkForUnknownMessage(state, testCase);
        assertTrue(AssertMsgs.WORKFLOW_NOT_EXECUTED, state.getWorkflowTrace().executedAsPlanned());
    }

    public static void receivedWarningAlert(State state, AnvilTestCase testCase) {
        checkForUnknownMessage(state, testCase);
        WorkflowTrace trace = state.getWorkflowTrace();
        smartExecutedAsPlanned(state, testCase);

        AlertMessage msg = trace.getFirstReceivedMessage(AlertMessage.class);
        assertNotNull(AssertMsgs.NO_WARNING_ALERT, msg);
        assertEquals(
                AssertMsgs.NO_WARNING_ALERT,
                AlertLevel.WARNING.getValue(),
                msg.getLevel().getValue().byteValue());
    }

    public static void testAlertDescription(State state, AnvilTestCase testCase, AlertDescription expected, AlertMessage msg) {
        testAlertDescription(state, testCase, new AlertDescription[] {expected}, msg);
    }

    public static void testAlertDescription(State state, AnvilTestCase testCase, AlertDescription[] expected, AlertMessage msg) {
        if (msg == null) {
            testCase.addAdditionalResultInfo("No alert received to test description for");
            return;
        }

        if (WorkflowTraceUtil.getLastReceivedMessage(
                        ProtocolMessageType.ALERT, state.getWorkflowTrace())
                != msg) {
            testCase.addAdditionalResultInfo(
                    "Received multiple Alerts - description of first Alert was tested");
        }

        AlertDescription received =
                AlertDescription.getAlertDescription(msg.getDescription().getValue());
        List<AlertDescription> expectedList = Arrays.asList(expected);
        if (!expectedList.contains(received)) {
            testCase.addAdditionalResultInfo("Unexpected Alert Description");
            testCase.addAdditionalResultInfo(
                    String.format(
                            "Expected: %s",
                            expectedList.stream()
                                    .map(AlertDescription::name)
                                    .collect(Collectors.joining(","))));
            testCase.addAdditionalResultInfo(String.format("Received: %s", received));
            testCase.setTestResult(TestResult.CONCEPTUALLY_SUCCEEDED);
            LOGGER.debug(testCase.getAdditionalResultInformation());
        }
    }

    public static void testAlertDescription(State state, AnvilTestCase testCase, AlertDescription... expected) {
        AlertMessage alert = state.getWorkflowTrace().getFirstReceivedMessage(AlertMessage.class);
        testAlertDescription(state, testCase, expected, alert);
    }

    public static void smartExecutedAsPlanned(State state, AnvilTestCase testCase) {
        checkForUnknownMessage(state, testCase);
        WorkflowTrace trace = state.getWorkflowTrace();
        if (state.getTlsContext().isReceivedMessageWithWrongTls13KeyType()
                && state.getTlsContext().getActiveKeySetTypeRead()
                        != Tls13KeySetType.NONE) {
            throw new AssertionError("Peer used wrong TLS 1.3 KeySetType to protect records");
        }
        boolean executedAsPlanned = trace.executedAsPlanned();
        if (executedAsPlanned) return;

        TcpFragmentationDerivation tcpFragmentation = null;
        if (testCase.getParameterCombination() != null) {
            tcpFragmentation =
                    testCase.getParameterCombination().getParameter(TcpFragmentationDerivation.class);
        }
        boolean onlyCheckActionsBeforeLastSendingFlight =
                tcpFragmentation != null && tcpFragmentation.getSelectedValue();

        List<TlsAction> tlsActions = trace.getTlsActions();
        TlsAction lastSendingAction = (TlsAction) trace.getLastSendingAction();
        TlsAction lastReceivingAction = (TlsAction) trace.getLastReceivingAction();
        int lastReceivingFlightIndex =
                lastReceivingAction != null
                        ? tlsActions.indexOf(lastReceivingAction)
                        : tlsActions.size();
        int lastSendingFlightIndex =
                lastSendingAction != null
                        ? tlsActions.indexOf(lastSendingAction)
                        : tlsActions.size();

        for (int i = tlsActions.size() - 1; i > 0; i--) {
            TlsAction action = tlsActions.get(i);
            if (action instanceof ReceivingAction && i == lastReceivingFlightIndex - 1) {
                lastReceivingFlightIndex = i;
            }
            if (action instanceof SendingAction && i == lastSendingFlightIndex - 1) {
                lastSendingFlightIndex = i;
            }

            // onlyCheckActionsBeforeLastSendingFlight = true
            //   <=> if (i < lastReceivingFlightIndex && i < lastSendingFlightIndex)
            // onlyCheckActionsBeforeLastSendingFlight = false
            //   <=> if (i < lastReceivingFlightIndex)
            if (i < lastReceivingFlightIndex
                    && (i < lastSendingFlightIndex || !onlyCheckActionsBeforeLastSendingFlight)) {
                if (!action.executedAsPlanned()) {
                    throw new AssertionError(
                            String.format(
                                    "Action at index %d could not be executed as planned: %s",
                                    i, action.toString()));
                }
            }
        }

        if (!ReceivingAction.class.isAssignableFrom(trace.getLastMessageAction().getClass())) {
            throw new AssertionError("Last action is not a receiving action");
        }

        if (lastReceivingAction instanceof ReceiveAction) {
            ReceiveAction action = (ReceiveAction) lastReceivingAction;
            List<ProtocolMessage> expectedMessages = action.getExpectedMessages();
            List<ProtocolMessage> receivedMessages = action.getReceivedMessages();
            if (receivedMessages == null) {
                receivedMessages = new ArrayList<>();
            }

            ProtocolMessage lastExpected =
                    (ProtocolMessage) expectedMessages.get(expectedMessages.size() - 1);
            if (lastExpected.getClass().equals(AlertMessage.class)) {
                if (receivedMessages.size() > 0) {
                    ProtocolMessage lastReceivedMessage =
                            receivedMessages.get(receivedMessages.size() - 1);
                    if (lastReceivedMessage.getClass().equals(AlertMessage.class)) {
                        boolean lastMessageIsFatalAlert =
                                AlertLevel.FATAL
                                        == AlertLevel.getAlertLevel(
                                                ((AlertMessage) lastReceivedMessage)
                                                        .getLevel()
                                                        .getValue());
                        if (lastMessageIsFatalAlert
                                || onlyValidAlertsAfterFatalAlert(action.getReceivedMessages())) {
                            return;
                        }
                    } else if (lastMessagesAreTooEarlyEncryptedAlertsTls13(state, testCase, action)) {
                        return;
                    }
                }

                if (expectedMessages.size() > 1 && !action.executedAsPlanned()) {
                    throw new AssertionError(
                            "Last receive action did not execute as planned: " + action.toString());
                }

                return;
            }
        } else if (lastReceivingAction instanceof ReceiveTillAction) {
            ReceiveTillAction action = (ReceiveTillAction) lastReceivingAction;
            ProtocolMessage expectedMessage = action.getWaitTillMessage();
            List<ProtocolMessage> messages = action.getReceivedMessages();

            if (action.getReceivedMessages().isEmpty()
                    && expectedMessage.getClass().equals(AlertMessage.class)) {
                return;
            } else if (messages.get(messages.size() - 1).getClass().equals(AlertMessage.class)) {
                return;
            }
        } else if (lastReceivingAction instanceof GenericReceiveAction) {
            return;
        }

        throw new AssertionError("Last action is not an expected receiving action");
    }

    /**
     * This method is intended to allow cases where a Fatal Alert is followed by a Close Notify.
     * Multiple other alerts are also acceptable but should be reviewed (we set an additional result
     * info for this in receivedFatalAlert).
     */
    private static boolean onlyValidAlertsAfterFatalAlert(List<ProtocolMessage> receivedMessages) {
        // upon calling this function, we already know there is at least 1
        // alert at the end
        if (receivedMessages.size() < 2) {
            return false;
        }

        boolean foundFatal = false;
        for (ProtocolMessage msg : receivedMessages) {
            if (msg instanceof AlertMessage) {
                AlertMessage alert = (AlertMessage) msg;
                if (alert.getLevel().getValue() == AlertLevel.FATAL.getValue()) {
                    foundFatal = true;
                } else if (alert.getLevel().getValue() != AlertLevel.WARNING.getValue()) {
                    // If it's neither FATAL nor WARNING, we're probably interpreting
                    // a single encrypted alert as multiple alerts. This is due to the
                    // way we parse messages; return false to fail executedAsPlanned
                    return false;
                }
            } else if (foundFatal) {
                return false;
            }
        }

        return foundFatal;
    }

    /**
     * Some implementations switch to Handshake Traffic secrets too early, we thus haven't set up
     * the decryption in the record layer yet. We attempt to decrypt records with Handshake Secrets
     * to uncover these Alerts. We apply the same tolerance as for TLS 1.2 - the received messages
     * must either end with a Fatal Alert of it's own or may only consist of Alerts of valid
     * severity after receiving the first Fatal Alert (again to allow a Close Notify mostly)
     */
    private static boolean lastMessagesAreTooEarlyEncryptedAlertsTls13(State state, AnvilTestCase testCase, ReceiveAction lastReceiveAction) {
        ProtocolMessage lastReceivedMessage =
                lastReceiveAction
                        .getReceivedMessages()
                        .get(lastReceiveAction.getReceivedMessages().size() - 1);
        List<ProtocolMessage> receivedMessages = lastReceiveAction.getReceivedMessages();
        List<Record> receivedRecords = lastReceiveAction.getReceivedRecords();
        Record lastAbstractRecord =
                lastReceiveAction.getReceivedRecords().get(receivedRecords.size() - 1);
        if (lastAbstractRecord instanceof Record) {
            Record lastReceivedRecord = (Record) lastAbstractRecord;
            int expectedFirstEncryptedRecordIndex = 0;
            if (receivedMessages.get(0) instanceof ChangeCipherSpecMessage) {
                expectedFirstEncryptedRecordIndex = 1;
            }
            if (state.getConfig().getHighestProtocolVersion() == ProtocolVersion.TLS13
                    && TestContext.getInstance().getConfig().getTestEndpointMode()
                            == TestEndpointType.CLIENT
                    && state.getTlsContext().getActiveClientKeySetType()
                            == Tls13KeySetType.NONE
                    && lastReceivedMessage instanceof ApplicationMessage) {
                testCase.addAdditionalResultInfo(
                        "Received Application Message before decryption was set");

                List<ProtocolMessage> decryptedAlerts = new LinkedList<>();
                AlertMessage potentialAlert = null;

                for (int i = expectedFirstEncryptedRecordIndex; i < receivedRecords.size(); i++) {
                    Record recordToDecrypt = ((Record) receivedRecords.get(i));
                    recordToDecrypt.setSequenceNumber(
                            Modifiable.explicit(
                                    BigInteger.valueOf(i - expectedFirstEncryptedRecordIndex)));
                    potentialAlert =
                            tryToDecryptRecordWithHandshakeSecrets(
                                    state.getTlsContext(), lastReceivedRecord);

                    if (potentialAlert != null) {
                        testCase.addAdditionalResultInfo("Client encrypted Alert too early");
                        decryptedAlerts.add(potentialAlert);
                    } else if (decryptedAlerts.size() > 0) {
                        // chain of Alerts was interrupted by other message type
                        // or decryption failed
                        testCase.addAdditionalResultInfo("Not all Application Messages were Alerts");
                        return false;
                    }
                }

                // replace messages for further evaluation
                for (int i = expectedFirstEncryptedRecordIndex; i < receivedMessages.size(); i++) {
                    receivedMessages.remove(i);
                    receivedMessages.add(
                            i, decryptedAlerts.get(i - expectedFirstEncryptedRecordIndex));
                }

                if (potentialAlert != null
                        && potentialAlert.getLevel().getValue() == AlertLevel.FATAL.getValue()) {
                    // last is Fatal Alert
                    return true;
                } else if (!decryptedAlerts.isEmpty()) {
                    // also allow additional (Warning) Alerts if they follow a Fatal Alert
                    return onlyValidAlertsAfterFatalAlert(decryptedAlerts);
                }
            }
        }
        return false;
    }

    private static AlertMessage tryToDecryptRecordWithHandshakeSecrets(
            TlsContext context, Record record) {
        try {
            KeySet keySet =
                    KeySetGenerator.generateKeySet(
                            context,
                            ProtocolVersion.TLS13,
                            Tls13KeySetType.HANDSHAKE_TRAFFIC_SECRETS);
            RecordCipher recordCipher = RecordCipherFactory.getRecordCipher(context, keySet, false);
            RecordDecryptor dec = new RecordDecryptor(recordCipher, context);
            dec.decrypt(record);
            if (record.getContentMessageType() == ProtocolMessageType.ALERT) {
                AlertMessage alert = new AlertMessage();
                alert.getParser(
                                context,
                                new ByteArrayInputStream(
                                        record.getCleanProtocolMessageBytes().getValue()))
                        .parse(alert);
                return alert;
            }
            return null;
        } catch (Exception ex) {
            return null;
        }
    }

    private static boolean traceFailedBeforeAlertAction(WorkflowTrace workflowTrace) {
        TlsAction alertReceivingAction =
                WorkflowTraceUtil.getFirstReceivingActionForMessage(
                        ProtocolMessageType.ALERT, workflowTrace);
        TlsAction lastReceiveAction = (TlsAction) workflowTrace.getLastReceivingAction();
        if (alertReceivingAction == null
                && lastReceiveAction != null
                && lastReceiveAction instanceof GenericReceiveAction) {
            alertReceivingAction = lastReceiveAction;
        }
        TlsAction firstFailed = WorkflowTraceUtil.getFirstFailedAction(workflowTrace);
        return firstFailed != alertReceivingAction
                && workflowTrace.getTlsActions().indexOf(firstFailed)
                        < workflowTrace.getTlsActions().indexOf(alertReceivingAction);
    }
}
