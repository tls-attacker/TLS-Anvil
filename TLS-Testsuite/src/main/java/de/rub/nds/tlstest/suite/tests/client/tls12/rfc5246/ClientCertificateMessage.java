package de.rub.nds.tlstest.suite.tests.client.tls12.rfc5246;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.annotations.ClientTest;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import static org.junit.Assert.*;

@ClientTest
@RFC(number = 5446, section = "7.4.6. Client Certificate")
public class ClientCertificateMessage extends Tls12Test {

    @TlsTest(description = "If no suitable certificate is available, the client MUST send a certificate message containing no certificates.")
    public void clientMustSendCertMsg(WorkflowRunner runner) {
        runner.replaceSelectedCiphersuite = true;

        Config c = this.getConfig();
        c.setClientAuthentication(true);
        runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);

        runner.execute(new WorkflowTrace(), c).validateFinal(i -> {
            assertNotNull("Client didn't send CertificateMessage", i.getWorkflowTrace().getFirstReceivedMessage(CertificateMessage.class));
        });
    }

}
