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
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceConfigurationUtil;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceResultUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Tag;

@ClientTest
public class ClientAuthentication extends Tls13Test {

    @AnvilTest(id = "8446-bejcyb2cLf")
    @Tag("adjusted")
    public void clientSendsCertificateAndFinMessage(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);
        c.setClientAuthentication(true);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);

        HandshakeMessage certificateVerify =
                WorkflowTraceConfigurationUtil.getLastStaticConfiguredReceiveMessage(
                        workflowTrace, HandshakeMessageType.CERTIFICATE_VERIFY);
        certificateVerify.setRequired(false);

        State state = runner.execute(workflowTrace, c);
        Validator.executedAsPlanned(state, testCase);

        CertificateMessage certificateMessage =
                (CertificateMessage)
                        WorkflowTraceResultUtil.getLastReceivedMessage(
                                state.getWorkflowTrace(), HandshakeMessageType.CERTIFICATE);

        if (certificateMessage.getCertificatesListLength().getValue() == 0) {
            Assertions.assertFalse(
                    WorkflowTraceResultUtil.didReceiveMessage(
                            state.getWorkflowTrace(), HandshakeMessageType.CERTIFICATE_VERIFY),
                    "Received CertificateVerify message even though an empty certificate was provided.");
        }
    }
}
