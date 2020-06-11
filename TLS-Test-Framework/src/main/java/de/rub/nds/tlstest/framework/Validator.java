package de.rub.nds.tlstest.framework;

import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlstest.framework.constants.AssertMsgs;
import de.rub.nds.tlstest.framework.constants.TestStatus;
import de.rub.nds.tlstest.framework.execution.AnnotatedState;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import static org.junit.Assert.*;

public class Validator {
    private static final Logger LOGGER = LogManager.getLogger();

    public static void receivedFatalAlert(AnnotatedState i) {
        WorkflowTrace trace = i.getWorkflowTrace();
        assertTrue(AssertMsgs.WorkflowNotExecuted, trace.smartExecutedAsPlanned());

        AlertMessage msg = trace.getFirstReceivedMessage(AlertMessage.class);
        if (msg == null) {
            i.addAdditionalResultInfo("Timeout");
            i.setStatus(TestStatus.PARTIALLY_FAILED);
            LOGGER.warn("Timeout");
            return;
        }
        assertEquals(AssertMsgs.NoFatalAlert, AlertLevel.FATAL.getValue(), msg.getLevel().getValue().byteValue());
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

        AlertDescription received = AlertDescription.getAlertDescription(msg.getDescription().getValue().byteValue());
        if (expexted != received) {
            i.addAdditionalResultInfo("Unexpected Alert Description");
            i.addAdditionalResultInfo(String.format("Expected: %s", expexted));
            i.addAdditionalResultInfo(String.format("Received: %s", received));
            LOGGER.warn(i.getAdditionalResultInformation());
        }
    }

}
