package de.rub.nds.tlstest.suite.tests.server.tls13.rfc8446;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.ServerTest;
import de.rub.nds.anvilcore.teststate.AnvilTestCase;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateRequestMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Tag;

@ServerTest
public class ClientAuthentication extends Tls13Test {
    // TODO add a @MethodCondition to only run this test if the server sends a CertificateRequest
    // (no feature-extraction property for this exists yet)
    @AnvilTest(id = "8446-ed8c230621")
    @Tag("rfc8446-coverage")
    @Disabled
    public void certificateRequestContainsSignAlgoExtension(
            AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);
        config.setSupportedVersions(ProtocolVersion.TLS13);
        config.setClientAuthentication(true);

        WorkflowTrace trace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        State state = runner.execute(trace, config);

        // The statement only concerns the CertificateRequest message, so a completed handshake
        // is not required.
        CertificateRequestMessage certificateRequest =
                state.getWorkflowTrace().getFirstReceivedMessage(CertificateRequestMessage.class);
        Assertions.assertNotNull(certificateRequest, "No CertificateRequest was received");
        Assertions.assertTrue(
                certificateRequest.containsExtension(ExtensionType.SIGNATURE_AND_HASH_ALGORITHMS),
                "CertificateRequest did not contain a signature_algorithms extension");
    }
}
