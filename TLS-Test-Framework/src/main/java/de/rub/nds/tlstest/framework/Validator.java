package de.rub.nds.tlstest.framework;

import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.transport.socket.SocketState;
import de.rub.nds.tlstest.framework.constants.AssertMsgs;
import de.rub.nds.tlstest.framework.constants.TestStatus;
import de.rub.nds.tlstest.framework.execution.AnnotatedState;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

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
            assertTrue(AssertMsgs.WorkflowNotExecuted, trace.smartExecutedAsPlanned());
        }

        AlertMessage msg = trace.getFirstReceivedMessage(AlertMessage.class);
        boolean socketClosed = socketClosed(i);
        if (msg == null && socketClosed) {
            i.addAdditionalResultInfo("Timeout");
            i.setStatus(TestStatus.PARTIALLY_SUCCEEDED);
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
        assertTrue(AssertMsgs.WorkflowNotExecuted, trace.smartExecutedAsPlanned());

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
            i.setStatus(TestStatus.PARTIALLY_SUCCEEDED);
            LOGGER.debug(i.getAdditionalResultInformation());
        }
    }

}
