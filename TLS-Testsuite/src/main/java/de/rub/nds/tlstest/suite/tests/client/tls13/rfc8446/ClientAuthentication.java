package de.rub.nds.tlstest.suite.tests.client.tls13.rfc8446;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.ClientTest;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;

@ClientTest
@RFC(number = 8446, section = "4.4.2. Certificate")
public class ClientAuthentication extends Tls13Test {

    @TlsTest(description = "If the server requests client authentication but no " +
            "suitable certificate is available, the client MUST send a " +
            "Certificate message containing no certificates.", interoperabilitySeverity = SeverityLevel.HIGH)
    public void clientSendsCertificateMessage(WorkflowRunner runner) {
        runner.replaceSelectedCiphersuite = true;

        Config c = this.getConfig();
        c.setClientAuthentication(true);

        WorkflowTrace workflowTrace = runner.generateWorkflowTraceUntilReceivingMessage(WorkflowTraceType.HANDSHAKE, HandshakeMessageType.CERTIFICATE_VERIFY);

        runner.setStateModifier(i -> {
            ((ReceiveAction)i.getWorkflowTrace().getLastReceivingAction()).setCheckOnlyExpected(true);
            return null;
        });

        runner.execute(workflowTrace, c).validateFinal(Validator::executedAsPlanned);
    }
}
