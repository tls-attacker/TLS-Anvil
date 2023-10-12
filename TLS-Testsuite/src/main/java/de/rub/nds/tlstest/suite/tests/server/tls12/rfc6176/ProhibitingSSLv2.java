/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.server.tls12.rfc6176;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.ServerTest;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2ClientHelloMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.EnforcedSenderRestriction;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@ServerTest
public class ProhibitingSSLv2 extends Tls12Test {

    @AnvilTest(id = "6176-KmcHZWR21g")
    @EnforcedSenderRestriction
    public void sendSSL2CompatibleClientHello(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                new SendAction(new SSL2ClientHelloMessage()),
                new ReceiveAction(new AlertMessage()));

        runner.execute(workflowTrace, c).validateFinal(Validator::receivedFatalAlert);
    }

    @AnvilTest(id = "6176-UvTTXNibXJ")
    public void sendClientHelloVersionLower0300(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        ClientHelloMessage clientHelloMessage = new ClientHelloMessage(c);
        clientHelloMessage.setProtocolVersion(Modifiable.explicit(ProtocolVersion.SSL2.getValue()));

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                new SendAction(clientHelloMessage), new ReceiveAction(new AlertMessage()));

        runner.execute(workflowTrace, c).validateFinal(Validator::receivedFatalAlert);
    }
}
