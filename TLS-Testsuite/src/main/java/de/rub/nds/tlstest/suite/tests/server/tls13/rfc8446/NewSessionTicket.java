/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.server.tls13.rfc8446;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.MethodCondition;
import de.rub.nds.anvilcore.annotation.ServerTest;
import de.rub.nds.anvilcore.teststate.AnvilTestCase;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.message.NewSessionTicketMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.GenericReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
import java.util.Arrays;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;

@ServerTest
public class NewSessionTicket extends Tls13Test {

    public ConditionEvaluationResult issuesTickets() {
        if (context.getFeatureExtractionResult()
                        .getResult(TlsAnalyzedProperty.ISSUES_TLS13_SESSION_TICKETS_AFTER_HANDSHAKE)
                == TestResults.TRUE) {
            return ConditionEvaluationResult.enabled("");
        } else {
            return ConditionEvaluationResult.disabled("Does not send TLS 1.3 session tickets");
        }
    }

    @AnvilTest(id = "8446-Av3GbEztrR")
    @MethodCondition(method = "issuesTickets")
    @Tag("new")
    public void newSessionTicketsAreValid(AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);
        config.setAddPSKKeyExchangeModesExtension(true);
        adjustPreSharedKeyModes(config);
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        // wait for possible NewSessionTicket
        workflowTrace.addTlsAction(new GenericReceiveAction());

        State state = runner.execute(workflowTrace, config);

        if (workflowTrace.getFirstReceivedMessage(NewSessionTicketMessage.class) != null) {
            NewSessionTicketMessage firstTicket =
                    workflowTrace.getFirstReceivedMessage(NewSessionTicketMessage.class);
            assertTrue(
                    firstTicket.getTicketLifetimeHint().getValue() <= 604800,
                    "Ticket lifetime of "
                            + firstTicket.getTicketLifetimeHint().getValue()
                            + " exceeds maximum of 604800");
            if (workflowTrace.getLastReceivedMessage(NewSessionTicketMessage.class)
                    != firstTicket) {
                NewSessionTicketMessage secondTicket =
                        workflowTrace.getLastReceivedMessage(NewSessionTicketMessage.class);
                assertFalse(
                        Arrays.equals(
                                firstTicket.getTicket().getTicketAgeAdd().getValue(),
                                secondTicket.getTicket().getTicketAgeAdd().getValue()),
                        "Found two tickets with identical ticket age add value");
            }
        }
    }
}
