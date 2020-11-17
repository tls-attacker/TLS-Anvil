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
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceivingAction;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;
import de.rub.nds.tlsattacker.transport.socket.SocketState;
import de.rub.nds.tlstest.framework.constants.AssertMsgs;
import de.rub.nds.tlstest.framework.constants.TestResult;
import de.rub.nds.tlstest.framework.execution.AnnotatedState;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.ArrayList;
import java.util.List;

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
            assertTrue(AssertMsgs.WorkflowNotExecuted, Validator.smartExecutedAsPlanned(trace));
        }

        AlertMessage msg = trace.getFirstReceivedMessage(AlertMessage.class);
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
    }

    public static void receivedFatalAlert(AnnotatedState i) {
        receivedFatalAlert(i, true);
    }

    public static void executedAsPlanned(AnnotatedState i) {
        assertTrue(AssertMsgs.WorkflowNotExecuted, i.getWorkflowTrace().executedAsPlanned());
    }

    public static void receivedWarningAlert(AnnotatedState i) {
        WorkflowTrace trace = i.getWorkflowTrace();
        assertTrue(AssertMsgs.WorkflowNotExecuted, Validator.smartExecutedAsPlanned(trace));

        AlertMessage msg = trace.getFirstReceivedMessage(AlertMessage.class);
        assertNotNull(AssertMsgs.NoWarningAlert, msg);
        assertEquals(AssertMsgs.NoWarningAlert, AlertLevel.WARNING.getValue(), msg.getLevel().getValue().byteValue());
    }

    public static void testAlertDescription(AnnotatedState i, AlertDescription expexted, AlertMessage msg) {
        if (msg == null) {
            i.addAdditionalResultInfo("Unexpected Alert Description, no alert received!");
            return;
        }

        AlertDescription received = AlertDescription.getAlertDescription(msg.getDescription().getValue());
        if (expexted != received) {
            i.addAdditionalResultInfo("Unexpected Alert Description");
            i.addAdditionalResultInfo(String.format("Expected: %s", expexted));
            i.addAdditionalResultInfo(String.format("Received: %s", received));
            i.setResult(TestResult.PARTIALLY_SUCCEEDED);
            LOGGER.debug(i.getAdditionalResultInformation());
        }
    }


    public static boolean smartExecutedAsPlanned(WorkflowTrace trace) {
        boolean executedAsPlanned = trace.executedAsPlanned();
        if (executedAsPlanned)
            return true;

        List<TlsAction> tlsActions = trace.getTlsActions();
        for (TlsAction action : tlsActions.subList(0, tlsActions.size() - 1)) {
            if (!action.executedAsPlanned()) {
                return false;
            }
        }

        if (!ReceivingAction.class.isAssignableFrom(trace.getLastMessageAction().getClass())) {
            return false;
        }

        if (trace.getLastReceivingAction().getClass().equals(ReceiveAction.class)) {
            ReceiveAction action = (ReceiveAction) trace.getLastReceivingAction();
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
                        boolean isFatalAlert =
                                AlertLevel.FATAL == AlertLevel.getAlertLevel(((AlertMessage)lastReceivedMessage).getLevel().getValue());
                        if (isFatalAlert) {
                            return true;
                        }
                    }
                }

                if (expectedMessages.size() > receivedMessages.size()) {
                    // try to delete the last expected AlertMessage and execute
                    // executedAsPlanned again. (In case of timeouts)
                    expectedMessages.remove(lastExpected);
                }

                return trace.executedAsPlanned();
            }
        } else if (trace.getLastReceivingAction().getClass().equals(ReceiveTillAction.class)) {
            ReceiveTillAction action = (ReceiveTillAction) trace.getLastReceivingAction();
            ProtocolMessage expectedMessage = action.getWaitTillMessage();
            List<ProtocolMessage> messages = action.getReceivedMessages();

            if (action.getReceivedMessages().size() == 0 && expectedMessage.getClass().equals(AlertMessage.class)) {
                return true;
            } else if (messages.get(messages.size() - 1).getClass().equals(AlertMessage.class)) {
                return true;
            }
        }

        return false;
    }

}
