/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.server.tls13.rfc8446;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.ServerTest;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.EnforcedSenderRestriction;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@ServerTest
public class Cookie extends Tls13Test {

    @AnvilTest(id = "8446-i1e2R9UFD2")
    @EnforcedSenderRestriction
    public void clientHelloWithUnsolicitedCookieExtension(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);

        ClientHelloMessage clientHello = new ClientHelloMessage(config);
        clientHello.setExtensionBytes(
                Modifiable.insert(new byte[] {0x00, 44, 0x00, 0x03, 0x00, 0x01, 0x02}, 0));

        WorkflowTrace trace = new WorkflowTrace();
        trace.addTlsActions(new SendAction(clientHello), new ReceiveAction(new AlertMessage()));

        runner.execute(trace, config).validateFinal(Validator::receivedFatalAlert);
    }
}
