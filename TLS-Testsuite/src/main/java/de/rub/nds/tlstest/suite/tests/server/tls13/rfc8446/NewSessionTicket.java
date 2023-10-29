/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.server.tls13.rfc8446;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.MethodCondition;
import de.rub.nds.anvilcore.annotation.ServerTest;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.message.NewSessionTicketMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.GenericReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
import java.util.Arrays;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@ServerTest
public class NewSessionTicket extends Tls13Test {

    public ConditionEvaluationResult issuesTickets() {
        if (context.getFeatureExtractionResult()
                        .getResult(TlsAnalyzedProperty.SUPPORTS_TLS13_SESSION_TICKETS)
                == TestResults.TRUE) {
            return ConditionEvaluationResult.enabled("");
        } else {
            return ConditionEvaluationResult.disabled("Does not send TLS 1.3 session tickets");
        }
    }

    @AnvilTest(id = "8446-Av3GbEztrR")
    @MethodCondition(method = "issuesTickets")
    @Tag("new")
    public void newSessionTicketsAreValid(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        config.setAddPSKKeyExchangeModesExtension(true);
        adjustPreSharedKeyModes(config);
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        // wait for possible NewSessionTicket
        workflowTrace.addTlsAction(new GenericReceiveAction());

        runner.execute(workflowTrace, config)
                .validateFinal(
                        i -> {
                            if (workflowTrace.getFirstReceivedMessage(NewSessionTicketMessage.class)
                                    != null) {
                                NewSessionTicketMessage firstTicket =
                                        workflowTrace.getFirstReceivedMessage(
                                                NewSessionTicketMessage.class);
                                assertTrue(
                                        "Ticket lifetime of "
                                                + firstTicket.getTicketLifetimeHint().getValue()
                                                + " exceeds maximum of 604800",
                                        firstTicket.getTicketLifetimeHint().getValue() <= 604800);
                                if (workflowTrace.getLastReceivedMessage(
                                                NewSessionTicketMessage.class)
                                        != firstTicket) {
                                    NewSessionTicketMessage secondTicket =
                                            workflowTrace.getLastReceivedMessage(
                                                    NewSessionTicketMessage.class);
                                    assertFalse(
                                            "Found two tickets with identical ticket age add value",
                                            Arrays.equals(
                                                    firstTicket
                                                            .getTicket()
                                                            .getTicketAgeAdd()
                                                            .getValue(),
                                                    secondTicket
                                                            .getTicket()
                                                            .getTicketAgeAdd()
                                                            .getValue()));
                                }
                            }
                        });
    }
}
