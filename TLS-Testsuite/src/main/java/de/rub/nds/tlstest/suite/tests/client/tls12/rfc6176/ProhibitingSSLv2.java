/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.client.tls12.rfc6176;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.ClientTest;
import de.rub.nds.anvilcore.annotation.NonCombinatorialAnvilTest;
import de.rub.nds.anvilcore.teststate.AnvilTestCase;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceConfigurationUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.EnforcedSenderRestriction;
import de.rub.nds.tlstest.framework.annotations.TlsVersion;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;

@ClientTest
@TlsVersion(
        supported =
                ProtocolVersion
                        .TLS12) // explicitly exclude for DTLS as SSL2 versions are by definition
// not applicable in a DTLS context
public class ProhibitingSSLv2 extends Tls12Test {

    @AnvilTest(id = "6176-yZUPDLF21Z")
    public void sendSSL2CompatibleClientHello(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(new ReceiveAction(new SSL2ClientHelloMessage()));

        State state = runner.execute(workflowTrace, c);
        assertFalse(state.getWorkflowTrace().executedAsPlanned(), "Client sent SSLv2 ClientHello");
    }

    @AnvilTest(id = "6176-GVZT3xHaGE")
    @EnforcedSenderRestriction
    public void sendServerHelloVersionLower0300(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsActions(new ReceiveAction(new AlertMessage()));

        ((ServerHelloMessage)
                        WorkflowTraceConfigurationUtil.getFirstStaticConfiguredSendMessage(
                                workflowTrace, HandshakeMessageType.SERVER_HELLO))
                .setProtocolVersion(Modifiable.explicit(ProtocolVersion.SSL2.getValue()));

        State state = runner.execute(workflowTrace, c);
        Validator.receivedFatalAlert(state, testCase);
    }

    @NonCombinatorialAnvilTest(id = "6176-1zkQSbX7Qy")
    public void testClientHelloProtocolVersion() {
        ClientHelloMessage msg = context.getReceivedClientHelloMessage();
        assertFalse(
                msg.getProtocolVersion().getValue()[0] < 3,
                "ClientHello protocol version is less than 0x0300");
    }
}
