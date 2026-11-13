/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.client.tls13.rfc8446;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.ClientTest;
import de.rub.nds.anvilcore.teststate.AnvilTestCase;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.message.cert.CertificateEntry;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceConfigurationUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Tag;

@ClientTest
public class Certificate extends Tls13Test {

    @AnvilTest(id = "8446-vN4oMaYkC6")
    public void emptyCertificateMessage(AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);

        WorkflowTrace trace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        trace.addTlsActions(new ReceiveAction(new AlertMessage()));
        WorkflowTraceConfigurationUtil.getFirstStaticConfiguredSendMessage(
                        trace, HandshakeMessageType.CERTIFICATE)
                .setCompleteResultingMessage(
                        Modifiable.explicit(
                                new byte[] {HandshakeMessageType.CERTIFICATE.getValue(), 0, 0, 0}));

        State state = runner.execute(trace, config);

        Validator.receivedFatalAlert(state, testCase, AlertDescription.DECODE_ERROR);
    }

    @AnvilTest(id = "8446-cM4fvnBMce")
    public void emptyCertificateList(AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);

        WorkflowTrace trace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        trace.addTlsActions(new ReceiveAction(new AlertMessage()));
        ((CertificateMessage)
                        WorkflowTraceConfigurationUtil.getFirstStaticConfiguredSendMessage(
                                trace, HandshakeMessageType.CERTIFICATE))
                .setCertificatesListBytes(Modifiable.explicit(new byte[] {}));

        State state = runner.execute(trace, config);

        Validator.receivedFatalAlert(state, testCase, AlertDescription.DECODE_ERROR);
    }

    @AnvilTest(id = "8446-a91f7c3e62")
    @Tag("rfc8446-coverage")
    public void certificateEntryExtensionsWereRequested(
            AnvilTestCase testCase, WorkflowRunner runner) {
        // Request client authentication and receive the client's Certificate. Check that each
        // entry extension was requested in our CertificateRequest; an empty Certificate is allowed.
        Config config = getPreparedConfig(runner);
        config.setClientAuthentication(true);

        WorkflowTrace trace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        trace.addTlsAction(new ReceiveTillAction(new CertificateMessage()));

        State state = runner.execute(trace, config);
        Validator.executedAsPlanned(state, testCase);

        CertificateRequestMessage request =
                trace.getFirstSentMessage(CertificateRequestMessage.class);
        CertificateMessage certificate = trace.getFirstReceivedMessage(CertificateMessage.class);
        Assertions.assertNotNull(request, "No CertificateRequest was sent");
        Assertions.assertNotNull(certificate, "No client Certificate was received");

        List<ExtensionMessage> requestedExtensions = request.getExtensions();
        Assertions.assertNotNull(requestedExtensions, "CertificateRequest extensions unavailable");
        Assertions.assertNotNull(
                certificate.getCertificateEntryList(), "Certificate entries were not parsed");

        // loop over received certificates
        for (CertificateEntry entry : certificate.getCertificateEntryList()) {
            Assertions.assertNotNull(
                    entry.getExtensionList(), "CertificateEntry extensions were not parsed");
            // loop over extensions within that certificate
            for (ExtensionMessage extension : entry.getExtensionList()) {
                // make sure they match any requested extenison
                Assertions.assertTrue(
                        requestedExtensions.stream()
                                .anyMatch(
                                        requested ->
                                                Arrays.equals(
                                                        requested.getExtensionType().getValue(),
                                                        extension.getExtensionType().getValue())),
                        "CertificateEntry contains an extension absent from CertificateRequest");
            }
        }
    }
}
