/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.client.tls12.rfc6176;

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
import de.rub.nds.tlstest.framework.annotations.ClientTest;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.TestDescription;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.annotations.categories.Interoperability;
import de.rub.nds.tlstest.framework.annotations.categories.Security;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;

import static org.junit.Assert.assertFalse;
import org.junit.Test;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@RFC(number = 6176, section = "3")
@ClientTest
public class ProhibitingSSLv2 extends Tls12Test {

    @Test
    @Interoperability(SeverityLevel.CRITICAL)
    @Security(SeverityLevel.CRITICAL)
    @TestDescription("TLS clients MUST NOT send the SSL version 2.0 compatible CLIENT-"
            + "HELLO message format.")
    public void sendSSL2CompatibleClientHello(WorkflowRunner runner) {
        Config c = this.getConfig();

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                new ReceiveAction(new SSL2ClientHelloMessage())
        );

        runner.execute(workflowTrace, c).validateFinal(i -> {
            assertFalse("Client sent SSLv2 ClientHello", i.getWorkflowTrace().executedAsPlanned());
        });
    }

    @TlsTest(description = "TLS servers MUST NOT reply with an SSL 2.0 SERVER-HELLO with a"
            + "protocol version that is less than { 0x03, 0x00 } and instead MUST"
            + "abort the connection")
    @Interoperability(SeverityLevel.HIGH)
    @Security(SeverityLevel.HIGH)
    public void sendServerHelloVersionLower0300(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsActions(
                new ReceiveAction(new AlertMessage())
        );

        workflowTrace.getFirstSendMessage(ServerHelloMessage.class)
                .setProtocolVersion(Modifiable.explicit(ProtocolVersion.SSL2.getValue()));

        runner.execute(workflowTrace, c).validateFinal(Validator::receivedFatalAlert);
    }

    @Test
    @Interoperability(SeverityLevel.HIGH)
    @Security(SeverityLevel.MEDIUM)
    @TestDescription("Clients MUST NOT send any ClientHello message that specifies a protocol version less than { 0x03, 0x00 }.")
    public void testClientHelloProtocolVersion() {
        ClientHelloMessage msg = context.getReceivedClientHelloMessage();
        assertFalse("ClientHello protocol version is less than 0x0300", msg.getProtocolVersion().getValue()[0] < 3);
    }

}
