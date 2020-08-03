package de.rub.nds.tlstest.suite.tests.server.tls12.rfc5246;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.ServerTest;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;

@RFC(number = 5246, section = "7.4.1.2. Client Hello")
@ServerTest
public class ClientHello extends Tls12Test {

    @TlsTest(description = "If the list contains cipher suites the server does not recognize, support, " +
            "or wish to use, the server MUST ignore those cipher suites, and process the remaining ones as usual.", interoperabilitySeverity = SeverityLevel.CRITICAL)
    public void unknownCipherSuite(WorkflowRunner runner) {
        Config c = this.getConfig();
        runner.appendEachSupportedCiphersuiteToClientSupported = true;

        c.setDefaultClientSupportedCiphersuites();

        ClientHelloMessage clientHelloMessage = new ClientHelloMessage(c);
        clientHelloMessage.setCipherSuites(Modifiable.insert(new byte[]{(byte)0xfe, 0x00}, 0));

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                new SendAction(clientHelloMessage),
                new ReceiveTillAction(new ServerHelloDoneMessage())
        );

        runner.execute(workflowTrace, c).validateFinal(Validator::executedAsPlanned);
    }

    @TlsTest(description = "This vector MUST contain, and all implementations MUST support, CompressionMethod.null. " +
            "Thus, a client and server will always be able to agree on a compression method.", interoperabilitySeverity = SeverityLevel.CRITICAL)
    public void unknownCompressionMethod(WorkflowRunner runner) {
        Config c = this.getConfig();
        runner.replaceSupportedCiphersuites = true;

        ClientHelloMessage clientHelloMessage = new ClientHelloMessage(c);
        clientHelloMessage.setCompressions(Modifiable.explicit(new byte[]{0x00, 0x04}));

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                new SendAction(clientHelloMessage),
                new ReceiveTillAction(new ServerHelloDoneMessage())
        );

        runner.execute(workflowTrace, c).validateFinal(Validator::executedAsPlanned);
    }
}
