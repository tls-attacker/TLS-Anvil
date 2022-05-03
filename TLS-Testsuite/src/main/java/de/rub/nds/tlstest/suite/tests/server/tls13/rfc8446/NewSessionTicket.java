
package de.rub.nds.tlstest.suite.tests.server.tls13.rfc8446;

import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.PskKeyExchangeMode;
import de.rub.nds.tlsattacker.core.protocol.message.NewSessionTicketMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.GenericReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.MethodCondition;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.ServerTest;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.annotations.categories.ComplianceCategory;
import de.rub.nds.tlstest.framework.annotations.categories.HandshakeCategory;
import de.rub.nds.tlstest.framework.annotations.categories.InteroperabilityCategory;
import de.rub.nds.tlstest.framework.annotations.categories.SecurityCategory;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
import java.util.Arrays;
import org.junit.Assert;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@ServerTest
@RFC(number = 8446, section = "4.6.1.  New Session Ticket Message")
public class NewSessionTicket extends Tls13Test {
    
    public ConditionEvaluationResult issuesTickets() {
        if (context.getSiteReport().getResult(TlsAnalyzedProperty.SUPPORTS_TLS13_SESSION_TICKETS) == TestResult.TRUE) {
            return ConditionEvaluationResult.enabled("");
        } else {
            return ConditionEvaluationResult.disabled("Does not send TLS 1.3 session tickets");
        }
    }
    
    
    @TlsTest(description = "Indicates the lifetime in seconds as a 32-bit unsigned integer in network byte order from the time of "
            + "ticket issuance. Servers MUST NOT use any value greater than 604800 seconds (7 days). [...]"
            + "A securely generated, random 32-bit value that is " 
            + "used to obscure the age of the ticket that the client includes in "
            + "the \"pre_shared_key\" extension.  The client-side ticket age is "
            + "added to this value modulo 2^32 to obtain the value that is "
            + "transmitted by the client.  The server MUST generate a fresh value "
            + "for each ticket it sends.")
    @InteroperabilityCategory(SeverityLevel.MEDIUM)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @SecurityCategory(SeverityLevel.HIGH)
    @ComplianceCategory(SeverityLevel.HIGH)
    @MethodCondition(method = "issuesTickets")
    @Tag("new")
    public void newSessionTicketsAreValid(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        config.setAddPSKKeyExchangeModesExtension(true);
        adjustPreSharedKeyModes(config);
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        //wait for possible NewSessionTicket
        workflowTrace.addTlsAction(new GenericReceiveAction());

        runner.execute(workflowTrace, config).validateFinal(i -> {
            if(workflowTrace.getFirstReceivedMessage(NewSessionTicketMessage.class) != null) {
                NewSessionTicketMessage firstTicket = workflowTrace.getFirstReceivedMessage(NewSessionTicketMessage.class);
                assertTrue("Ticket lifetime of " + firstTicket.getTicketLifetimeHint().getValue() + " exceeds maximum of 604800", firstTicket.getTicketLifetimeHint().getValue() <= 604800);
                if(workflowTrace.getLastReceivedMessage(NewSessionTicketMessage.class) != firstTicket) {
                    NewSessionTicketMessage secondTicket = workflowTrace.getLastReceivedMessage(NewSessionTicketMessage.class);
                    assertFalse("Found two tickets with identical ticket age add value", Arrays.equals(firstTicket.getTicket().getTicketAgeAdd().getValue(), secondTicket.getTicket().getTicketAgeAdd().getValue()));
                }
            }
        });
    }
}
