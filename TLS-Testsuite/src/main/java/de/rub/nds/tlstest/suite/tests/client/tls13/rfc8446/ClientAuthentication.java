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
import de.rub.nds.anvilcore.annotation.MethodCondition;
import de.rub.nds.anvilcore.teststate.AnvilTestCase;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceConfigurationUtil;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceResultUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;

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

    public ConditionEvaluationResult doesNotOfferPostHandshakeAuth() {
        if (context.getReceivedClientHelloMessage()
                .containsExtension(ExtensionType.POST_HANDSHAKE_AUTH)) {
            return ConditionEvaluationResult.disabled(
                    "Client offers post-handshake authentication");
        }
        return ConditionEvaluationResult.enabled("");
    }

    @AnvilTest(id = "8446-690f75da34")
    @Tag("rfc8446-coverage")
    @MethodCondition(method = "doesNotOfferPostHandshakeAuth")
    public void serverSendsCertificateRequestWithoutPostHandshakeAuthExtension(
            AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        // request post handshake auth
        workflowTrace.addTlsActions(
                new SendAction(new CertificateRequestMessage(c)),
                new ReceiveAction(new AlertMessage()));

        State state = runner.execute(workflowTrace, c);

        Validator.receivedFatalAlert(state, testCase, AlertDescription.UNEXPECTED_MESSAGE);
    }

    @AnvilTest(id = "8446-45303effa7")
    @Tag("rfc8446-coverage")
    public void serverSendsCertificateRequestWithNonZeroPostHandshakeAuthInHandshake(
            AnvilTestCase testCase, WorkflowRunner runner) {

        // create client auth handshake
        Config c = getPreparedConfig(runner);
        c.setClientAuthentication(true);
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);

        // modify CertificateRequest to include a non-empty CertificateRequestContext
        CertificateRequestMessage crmsg =
                (CertificateRequestMessage)
                        WorkflowTraceConfigurationUtil.getFirstStaticConfiguredSendMessage(
                                workflowTrace, HandshakeMessageType.CERTIFICATE_REQUEST);
        crmsg.setCertificateRequestContext(new byte[] {0, 1, 2, 3, 4, 5, 6, 7, 8});

        // expect alert (after sending the Cert Request)
        State state = runner.execute(workflowTrace, c);
        Validator.receivedFatalAlert(state, testCase);
    }
}
