package de.rub.nds.tlstest.suite.tests.server.tls13.rfc8446;

import com.sun.security.ntlm.Client;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.cert.CertificateEntry;
import de.rub.nds.tlsattacker.core.protocol.message.cert.CertificatePair;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ChangeConfigAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
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
import javafx.scene.control.Alert;

import java.util.List;

import static org.junit.Assert.*;

@ServerTest
@RFC(number = 8446, section = "4.1.2 Client Hello")
public class ClientHello extends Tls13Test {

    @TlsTest(description = "Because TLS 1.3 forbids renegotiation, if a server has negotiated " +
            "TLS 1.3 and receives a ClientHello at any other time, it MUST terminate the " +
            "connection with an \"unexpected_message\" alert.", interoperabilitySeverity = SeverityLevel.MEDIUM)
    public void noOverlappingParameters(WorkflowRunner runner) {
        Config config = this.getConfig();
        runner.replaceSupportedCiphersuites = true;

        WorkflowTrace trace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        trace.addTlsActions(
                new ChangeConfigAction<Boolean>("earlyStop", Boolean.FALSE),
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
            assertSame(AssertMsgs.UnexpectedAlertDescription, description, AlertDescription.UNEXPECTED_MESSAGE);
        });
    }

    @TlsTest(description = "In TLS 1.3, the client indicates its version preferences " +
            "in the \"supported_versions\" extension (Section 4.2.1) and the legacy_version " +
            "field MUST be set to 0x0303, which is the version number for TLS 1.2.")
    public void invalidLegacyVersion(WorkflowRunner runner) {
        Config config = this.getConfig();
        runner.replaceSupportedCiphersuites = true;

        ClientHelloMessage msg = new ClientHelloMessage(config);
        msg.setProtocolVersion(Modifiable.explicit(new byte[]{0x05, 0x05}));

        WorkflowTrace trace = new WorkflowTrace();
        trace.addTlsActions(
                new SendAction(msg),
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(trace, config).validateFinal(Validator::receivedFatalAlert);
    }

    @TlsTest(description = "For every TLS 1.3 ClientHello, this vector MUST contain " +
            "exactly one byte, set to zero, which corresponds to the \"null\" compression method in prior " +
            "versions of TLS. If a TLS 1.3 ClientHello is received with any other value in this field, " +
            "the server MUST abort the handshake with an \"illegal_parameter\" alert.", securitySeverity = SeverityLevel.MEDIUM)
    public void invalidCompression(WorkflowRunner runner) {
        Config config = this.getConfig();
        runner.replaceSupportedCiphersuites = true;

        ClientHelloMessage msg = new ClientHelloMessage(config);
        msg.setCompressions(Modifiable.explicit(new byte[]{0x01}));

        WorkflowTrace trace = new WorkflowTrace();
        trace.addTlsActions(
                new SendAction(msg),
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(trace, config).validateFinal(i -> {
            Validator.receivedFatalAlert(i);

            AlertMessage alert = i.getWorkflowTrace().getFirstReceivedMessage(AlertMessage.class);
            if (alert == null) {
                return;
            }

            AlertDescription description = AlertDescription.getAlertDescription(alert.getDescription().getValue());
            assertSame(AssertMsgs.UnexpectedAlertDescription, AlertDescription.ILLEGAL_PARAMETER, description);
        });
    }

}
