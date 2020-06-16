package de.rub.nds.tlstest.suite.tests.server.tls13.rfc8446;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.ServerTest;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;

@RFC(number = 8446, section = "4.2.3 Signature Algorithms")
@ServerTest
public class SignatureAlgorithms extends Tls13Test {

    @TlsTest(description = "If a server is authenticating via a certificate " +
            "and the client has not sent a \"signature_algorithms\" extension, " +
            "then the server MUST abort the handshake with " +
            "a \"missing_extension\" alert (see Section 9.2).")
    public void omitSignatureAlgorithmsExtension(WorkflowRunner runner) {
        runner.replaceSupportedCiphersuites = true;

        Config c = this.getConfig();
        c.setAddSignatureAndHashAlgorithmsExtension(false);

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                new SendAction(new ClientHelloMessage(c)),
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(workflowTrace, c).validateFinal(i -> {
            Validator.receivedFatalAlert(i);

            AlertMessage msg = i.getWorkflowTrace().getFirstReceivedMessage(AlertMessage.class);
            if (msg == null) return;
            Validator.testAlertDescription(i, AlertDescription.MISSING_EXTENSION, msg);
        });
    }
}
