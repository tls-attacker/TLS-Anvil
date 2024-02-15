/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.client.tls12.rfc6176;

import static org.junit.Assert.assertFalse;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.ClientTest;
import de.rub.nds.anvilcore.annotation.NonCombinatorialAnvilTest;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.EnforcedSenderRestriction;
import de.rub.nds.tlstest.framework.annotations.TlsVersion;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@ClientTest
@TlsVersion(
        supported =
                ProtocolVersion
                        .TLS12) // explicitly exclude for DTLS as SSL2 versions are by definition
// not applicable in a DTLS context
public class ProhibitingSSLv2 extends Tls12Test {

    @AnvilTest(id = "6176-yZUPDLF21Z")
    public void sendSSL2CompatibleClientHello(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(new ReceiveAction(new SSL2ClientHelloMessage()));

        runner.execute(workflowTrace, c)
                .validateFinal(
                        i -> {
                            assertFalse(
                                    "Client sent SSLv2 ClientHello",
                                    i.getWorkflowTrace().executedAsPlanned());
                        });
    }

    @AnvilTest(id = "6176-GVZT3xHaGE")
    @EnforcedSenderRestriction
    public void sendServerHelloVersionLower0300(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsActions(new ReceiveAction(new AlertMessage()));

        workflowTrace
                .getFirstSendMessage(ServerHelloMessage.class)
                .setProtocolVersion(Modifiable.explicit(ProtocolVersion.SSL2.getValue()));

        runner.execute(workflowTrace, c).validateFinal(Validator::receivedFatalAlert);
    }

    @NonCombinatorialAnvilTest(id = "6176-1zkQSbX7Qy")
    public void testClientHelloProtocolVersion() {
        ClientHelloMessage msg = context.getReceivedClientHelloMessage();
        assertFalse(
                "ClientHello protocol version is less than 0x0300",
                msg.getProtocolVersion().getValue()[0] < 3);
    }
}
