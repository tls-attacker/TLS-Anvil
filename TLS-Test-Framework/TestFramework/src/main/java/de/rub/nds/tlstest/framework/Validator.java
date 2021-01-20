/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework;

import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceivingAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendingAction;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;
import de.rub.nds.tlsattacker.transport.socket.SocketState;
import de.rub.nds.tlstest.framework.constants.AssertMsgs;
import de.rub.nds.tlstest.framework.constants.TestResult;
import de.rub.nds.tlstest.framework.execution.AnnotatedState;
import de.rub.nds.tlstest.framework.model.derivationParameter.TcpFragmentationDerivation;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.Assert.*;

public class Validator {
    private static final Logger LOGGER = LogManager.getLogger();

    public static boolean socketClosed(AnnotatedState i) {
        SocketState socketState = i.getState().getTlsContext().getFinalSocketState();
        return (socketState == SocketState.SOCKET_EXCEPTION || socketState == SocketState.CLOSED || socketState == SocketState.IO_EXCEPTION);
    }

    public static void receivedFatalAlert(AnnotatedState i, boolean checkExecutedAsPlanned) {
        WorkflowTrace trace = i.getWorkflowTrace();

        if (checkExecutedAsPlanned) {
            try {
                Validator.smartExecutedAsPlanned(i);
            } catch (Throwable e) {
                if(traceFailedBeforeAlertAction(trace)) {
                    i.addAdditionalResultInfo(AssertMsgs.WorkflowNotExecutedBeforeAlert);
                } else {
                    ReceivingAction alertReceivingAction = (ReceivingAction) WorkflowTraceUtil.getFirstReceivingActionForMessage(ProtocolMessageType.ALERT, trace);
                    i.addAdditionalResultInfo("Workflow failed at Alert receiving action. Received: " + alertReceivingAction.getReceivedMessages().stream().map(ProtocolMessage::toCompactString).collect(Collectors.joining(",")));
                }
                throw e;
            }
        }

        AlertMessage msg = trace.getFirstReceivedMessage(AlertMessage.class);
        boolean multipleAlerts = false;
        if(trace.getLastReceivedMessage(AlertMessage.class) != msg) {
            i.addAdditionalResultInfo("Received multiple Alerts while waiting for Fatal Alert");
            multipleAlerts = true;
        }
        boolean socketClosed = socketClosed(i);
        if (msg == null && socketClosed) {
            i.addAdditionalResultInfo("Timeout");
            i.setResult(TestResult.PARTIALLY_SUCCEEDED);
            LOGGER.debug("Timeout");
            return;
        }
        assertNotNull("No Alert message received and socket is still open.", msg);
        assertEquals(AssertMsgs.NoFatalAlert, AlertLevel.FATAL.getValue(), msg.getLevel().getValue().byteValue());
        assertTrue("Socket still open after fatal alert", socketClosed);
        
        if(multipleAlerts) {
            i.setResult(TestResult.PARTIALLY_SUCCEEDED);
        }
    }

    public static void receivedFatalAlert(AnnotatedState i) {
        receivedFatalAlert(i, true);
    }

    public static void executedAsPlanned(AnnotatedState i) {
        assertTrue(AssertMsgs.WorkflowNotExecuted, i.getWorkflowTrace().executedAsPlanned());
    }

    public static void receivedWarningAlert(AnnotatedState i) {
        WorkflowTrace trace = i.getWorkflowTrace();
        Validator.smartExecutedAsPlanned(i);

        AlertMessage msg = trace.getFirstReceivedMessage(AlertMessage.class);
        assertNotNull(AssertMsgs.NoWarningAlert, msg);
        assertEquals(AssertMsgs.NoWarningAlert, AlertLevel.WARNING.getValue(), msg.getLevel().getValue().byteValue());
    }

    public static void testAlertDescription(AnnotatedState i, AlertDescription expected, AlertMessage msg) {
        if (msg == null) {
            i.addAdditionalResultInfo("No alert received");
            return;
        }
        
        if(WorkflowTraceUtil.getLastReceivedMessage(ProtocolMessageType.ALERT, i.getWorkflowTrace()) != msg) {
            i.addAdditionalResultInfo("Received multiple Alerts");
        }

        AlertDescription received = AlertDescription.getAlertDescription(msg.getDescription().getValue());
        if (expected != received) {
            i.addAdditionalResultInfo("Unexpected Alert Description");
            i.addAdditionalResultInfo(String.format("Expected: %s", expected));
            i.addAdditionalResultInfo(String.format("Received: %s", received));
            i.setResult(TestResult.PARTIALLY_SUCCEEDED);
            LOGGER.debug(i.getAdditionalResultInformation());
        }
    }


    public static void smartExecutedAsPlanned(AnnotatedState state) {
        WorkflowTrace trace = state.getWorkflowTrace();
        boolean executedAsPlanned = trace.executedAsPlanned();
        if (executedAsPlanned)
            return;

        TcpFragmentationDerivation tcpFragmentation = null;
        if(state.getDerivationContainer() != null) {
            tcpFragmentation = state.getDerivationContainer().getDerivation(TcpFragmentationDerivation.class);
        }
        boolean onlyCheckActionsBeforeLastSendingFlight = tcpFragmentation != null && tcpFragmentation.getSelectedValue();

        List<TlsAction> tlsActions = trace.getTlsActions();
        TlsAction lastSendingAction = (TlsAction)trace.getLastSendingAction();
        TlsAction lastReceivingAction = (TlsAction)trace.getLastReceivingAction();
        int lastReceivingFlightIndex = lastReceivingAction != null ? tlsActions.indexOf(lastReceivingAction) : tlsActions.size();
        int lastSendingFlightIndex = lastSendingAction != null ? tlsActions.indexOf(lastSendingAction) : tlsActions.size();

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
            if (i < lastReceivingFlightIndex && (i < lastSendingFlightIndex || !onlyCheckActionsBeforeLastSendingFlight)) {
                if (!action.executedAsPlanned()) {
                    throw new AssertionError(String.format("Action at index %d could not be executed as planned", i));
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

            ProtocolMessage lastExpected = expectedMessages.get(expectedMessages.size() - 1);
            if (lastExpected.getClass().equals(AlertMessage.class)) {
                if (receivedMessages.size() > 0) {
                    ProtocolMessage lastReceivedMessage = receivedMessages.get(receivedMessages.size() - 1);
                    if (lastReceivedMessage.getClass().equals(AlertMessage.class)) {
                        boolean lastMessageIsFatalAlert =
                                AlertLevel.FATAL == AlertLevel.getAlertLevel(((AlertMessage)lastReceivedMessage).getLevel().getValue());
                        if (lastMessageIsFatalAlert || onlyValidAlertsAfterFatalAlert(action)) {
                            return;
                        }
                    }
                }

                if (expectedMessages.size() > receivedMessages.size()) {
                    // try to delete the last expected AlertMessage and execute
                    // executedAsPlanned again. (In case of timeouts)
                    expectedMessages.remove(lastExpected);
                }

                if (expectedMessages.size() > 0 && !action.executedAsPlanned()) {
                    expectedMessages.add(lastExpected);
                    throw new AssertionError("Last receive action did not execute as planned");
                }

                return;
            }
        } else if (lastReceivingAction instanceof ReceiveTillAction) {
            ReceiveTillAction action = (ReceiveTillAction) lastReceivingAction;
            ProtocolMessage expectedMessage = action.getWaitTillMessage();
            List<ProtocolMessage> messages = action.getReceivedMessages();

            if (action.getReceivedMessages().size() == 0 && expectedMessage.getClass().equals(AlertMessage.class)) {
                return;
            } else if (messages.get(messages.size() - 1).getClass().equals(AlertMessage.class)) {
                return;
            }
        }

        throw new AssertionError("Last action is not a receiving action");
    }
    
    /**
     * This method is intended to allow cases where a Fatal Alert is followed
     * by a Close Notify. Multiple other alerts are also acceptable but should
     * be reviewed (we set an additional result info for this in
     * receivedFatalAlert).
     */
    private static boolean onlyValidAlertsAfterFatalAlert(ReceiveAction lastReceive) {
        List<ProtocolMessage> receivedMessages = lastReceive.getReceivedMessages();
        
        //upon calling this function, we already know there is at least 1
        //alert at the end
        if(receivedMessages.size() < 2) {
            return false;
        }
        
        boolean foundFatal = false;
        for(ProtocolMessage msg: receivedMessages) {
            if(msg instanceof AlertMessage) {
                AlertMessage alert = (AlertMessage) msg;
                if(alert.getLevel().getValue() == AlertLevel.FATAL.getValue()) {
                    foundFatal = true;
                } else if(alert.getLevel().getValue() != AlertLevel.WARNING.getValue()) {
                    //If it's neither FATAL nor WARNING, we're probably interpreting
                    //a single encrypted alert as multiple alerts. This is due to the
                    //way we parse messages; return false to fail executedAsPlanned
                    return false;
                }
            } else if(foundFatal) {
                return false;
            }
        }
        
        return foundFatal;
    }

    private static boolean traceFailedBeforeAlertAction(WorkflowTrace workflowTrace) {
        TlsAction alertReceivingAction = WorkflowTraceUtil.getFirstReceivingActionForMessage(ProtocolMessageType.ALERT, workflowTrace);
        TlsAction firstFailed = WorkflowTraceUtil.getFirstFailedAction(workflowTrace);
        return firstFailed != alertReceivingAction && workflowTrace.getTlsActions().indexOf(firstFailed) < workflowTrace.getTlsActions().indexOf(alertReceivingAction);
    }

}
