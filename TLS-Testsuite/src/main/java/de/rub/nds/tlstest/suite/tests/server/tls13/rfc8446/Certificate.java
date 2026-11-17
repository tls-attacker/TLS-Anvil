/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.server.tls13.rfc8446;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.ServerTest;
import de.rub.nds.anvilcore.teststate.AnvilTestCase;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.cert.CertificateEntry;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
import java.util.Arrays;
import org.junit.jupiter.api.Tag;

@ServerTest
public class Certificate extends Tls13Test {

    @AnvilTest(id = "8446-d9fcJKjSny")
    @Tag("new")
    public void certificateListIsNotEmpty(AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        State state = runner.execute(workflowTrace, config);

        Validator.executedAsPlanned(state, testCase);
        CertificateMessage cert =
                state.getWorkflowTrace().getFirstReceivedMessage(CertificateMessage.class);
        assertTrue(
                cert.getCertificatesListLength().getValue() > 0,
                "Server's certificate list was emtpy");
    }

    @AnvilTest(id = "8446-a71f4c829b")
    @Tag("rfc8446-coverage")
    public void serverCertificateRequestContextIsEmpty(
            AnvilTestCase testCase, WorkflowRunner runner) {
        // Send ClientHello and receive the server flight, allowing optional client authentication.
        // Check that the received Certificate's request context contains no bytes.
        Config config = getPreparedConfig(runner);
        WorkflowTrace trace = runner.generateWorkflowTrace(WorkflowTraceType.DYNAMIC_HELLO);
        State state = runner.execute(trace, config);
        Validator.executedAsPlanned(state, testCase);

        CertificateMessage cert =
                state.getWorkflowTrace().getFirstReceivedMessage(CertificateMessage.class);
        assertNotNull(cert, "No server Certificate was received");
        assertNotNull(cert.getRequestContext(), "Certificate request context was not parsed");
        assertEquals(0, cert.getRequestContext().getValue().length);
    }

    @AnvilTest(id = "8446-b3d2e60f41")
    @Tag("rfc8446-coverage")
    public void serverCertificateExtensionsWereOffered(
            AnvilTestCase testCase, WorkflowRunner runner) {
        // Receive the server Certificate, then compare each entry's extension types with those
        // in our sent ClientHello. Every returned extension must have been offered.
        Config config = getPreparedConfig(runner);
        WorkflowTrace trace = runner.generateWorkflowTrace(WorkflowTraceType.DYNAMIC_HELLO);
        State state = runner.execute(trace, config);
        Validator.executedAsPlanned(state, testCase);

        ClientHelloMessage clientHello = trace.getFirstSentMessage(ClientHelloMessage.class);
        assertNotNull(clientHello, "No ClientHello was sent");
        assertNotNull(clientHello.getExtensions(), "ClientHello extensions were not parsed");

        CertificateMessage cert =
                state.getWorkflowTrace().getFirstReceivedMessage(CertificateMessage.class);

        assertNotNull(cert, "No server Certificate was received");
        assertNotNull(cert.getCertificateEntryList(), "Certificate entries were not parsed");
        assertTrue(!cert.getCertificateEntryList().isEmpty(), "Server Certificate has no entries");

        // loop over entries in certificate list
        for (CertificateEntry entry : cert.getCertificateEntryList()) {
            assertNotNull(entry.getExtensionList(), "Certificate entry extensions were not parsed");
            // loop over extensions on that entry
            for (ExtensionMessage certificateExtension : entry.getExtensionList()) {
                // make sure that every extension matches at least one of the clientHello extensions
                assertTrue(
                        clientHello.getExtensions().stream()
                                .map(ExtensionMessage::getExtensionType)
                                .anyMatch(
                                        offeredType ->
                                                Arrays.equals(
                                                        offeredType.getValue(),
                                                        certificateExtension
                                                                .getExtensionType()
                                                                .getValue())),
                        "Server Certificate contains an extension not offered in ClientHello");
            }
        }
    }
}
