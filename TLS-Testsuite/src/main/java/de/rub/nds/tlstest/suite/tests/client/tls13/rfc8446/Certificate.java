/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.client.tls13.rfc8446;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.ClientTest;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.annotations.categories.AlertCategory;
import de.rub.nds.tlstest.framework.annotations.categories.CertificateCategory;
import de.rub.nds.tlstest.framework.annotations.categories.ComplianceCategory;
import de.rub.nds.tlstest.framework.annotations.categories.HandshakeCategory;
import de.rub.nds.tlstest.framework.annotations.categories.SecurityCategory;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@ClientTest
@RFC(number = 8446, section = "4.4.2.4. Receiving a Certificate Message")
public class Certificate extends Tls13Test {

    @TlsTest(
            description =
                    "If the server supplies an empty Certificate message, "
                            + "the client MUST abort the handshake with a \"decode_error\" alert.")
    @HandshakeCategory(SeverityLevel.CRITICAL)
    @ComplianceCategory(SeverityLevel.CRITICAL)
    @SecurityCategory(SeverityLevel.HIGH)
    @CertificateCategory(SeverityLevel.CRITICAL)
    @AlertCategory(SeverityLevel.MEDIUM)
    public void emptyCertificateMessage(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);

        WorkflowTrace trace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        trace.addTlsActions(new ReceiveAction(new AlertMessage()));
        trace.getFirstSendMessage(CertificateMessage.class)
                .setCompleteResultingMessage(
                        Modifiable.explicit(
                                new byte[] {HandshakeMessageType.CERTIFICATE.getValue(), 0, 0, 0}));

        runner.execute(trace, config)
                .validateFinal(
                        i -> {
                            Validator.receivedFatalAlert(i);

                            AlertMessage alert =
                                    i.getWorkflowTrace()
                                            .getFirstReceivedMessage(AlertMessage.class);
                            Validator.testAlertDescription(i, AlertDescription.DECODE_ERROR, alert);
                        });
    }

    @TlsTest(
            description =
                    "If the server supplies an empty Certificate message, "
                            + "the client MUST abort the handshake with a \"decode_error\" alert.")
    @HandshakeCategory(SeverityLevel.CRITICAL)
    @ComplianceCategory(SeverityLevel.CRITICAL)
    @SecurityCategory(SeverityLevel.HIGH)
    @CertificateCategory(SeverityLevel.CRITICAL)
    @AlertCategory(SeverityLevel.MEDIUM)
    public void emptyCertificateList(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);

        WorkflowTrace trace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        trace.addTlsActions(new ReceiveAction(new AlertMessage()));
        trace.getFirstSendMessage(CertificateMessage.class)
                .setCertificatesListBytes(Modifiable.explicit(new byte[] {}));

        runner.execute(trace, config)
                .validateFinal(
                        i -> {
                            Validator.receivedFatalAlert(i);

                            AlertMessage alert =
                                    i.getWorkflowTrace()
                                            .getFirstReceivedMessage(AlertMessage.class);
                            Validator.testAlertDescription(i, AlertDescription.DECODE_ERROR, alert);
                        });
    }
}
