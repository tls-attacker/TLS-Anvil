package de.rub.nds.tlstest.suite.tests.server.tls13.rfc8446;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.ServerTest;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.constants.AssertMsgs;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.constants.TestStatus;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;

import java.util.Arrays;
import java.util.List;
import static org.junit.Assert.*;

@ServerTest
@RFC(number = 8446, section = "4.1.1 Cryptographic Negotiation")
public class CryptographicNegotiation extends Tls13Test {

    @TlsTest(description = "If the server is unable to negotiate a supported set of parameters " +
            "(i.e., there is no overlap between the client and server parameters), it MUST abort " +
            "the handshake with either a \"handshake_failure\" or \"insufficient_security\" fatal alert (see Section 6).", interoperabilitySeverity = SeverityLevel.MEDIUM)
    public void noOverlappingParameters(WorkflowRunner runner) {
        Config config = this.getConfig();
        runner.replaceSupportedCiphersuites = true;

        config.setDefaultClientNamedGroups(
                NamedGroup.GREASE_00,
                NamedGroup.GREASE_01,
                NamedGroup.GREASE_02,
                NamedGroup.GREASE_03,
                NamedGroup.GREASE_04
        );

        WorkflowTrace trace = new WorkflowTrace();
        trace.addTlsActions(
                new SendAction(new ClientHelloMessage(config)),
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(trace, config).validateFinal(i -> {
            Validator.receivedFatalAlert(i);

            AlertMessage alert = trace.getFirstReceivedMessage(AlertMessage.class);
            if (alert == null) {
                i.setStatus(TestStatus.PARTIALLY_FAILED);
                return;
            }

            AlertDescription description = AlertDescription.getAlertDescription(alert.getDescription().getValue());
            assertTrue(
                    AssertMsgs.UnexpectedAlertDescription,
                    description == AlertDescription.HANDSHAKE_FAILURE || description == AlertDescription.INSUFFICIENT_SECURITY
            );
        });
    }


}
