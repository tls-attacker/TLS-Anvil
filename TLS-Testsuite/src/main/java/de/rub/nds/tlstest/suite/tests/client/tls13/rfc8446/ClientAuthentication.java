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
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@ClientTest
public class ClientAuthentication extends Tls13Test {

    @AnvilTest(id = "8446-bejcyb2cLf")
    @Tag("adjusted")
    public void clientSendsCertificateAndFinMessage(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        c.setClientAuthentication(true);

        WorkflowTrace workflowTrace =
                runner.generateWorkflowTraceUntilReceivingMessage(
                        WorkflowTraceType.HANDSHAKE, HandshakeMessageType.CERTIFICATE_VERIFY);
        ((ReceiveAction)
                        workflowTrace.getTlsActions().get(workflowTrace.getTlsActions().size() - 1))
                .getExpectedMessages()
                .add(new FinishedMessage());
        runner.execute(workflowTrace, c).validateFinal(Validator::executedAsPlanned);
    }
}
