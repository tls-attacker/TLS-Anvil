package de.rub.nds.tlstest.suite.tests.server.tls12.rfc4492;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EllipticCurvesExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.ServerTest;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.constants.AssertMsgs;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.AnnotatedStateContainer;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;

import java.util.List;

import static org.junit.Assert.*;

@ServerTest
public class RespectClientExtensions extends Tls12Test {
    @RFC(number = 4492, section = "5.1. Client Hello Extensions")
    @TlsTest(description = "Servers implementing ECC cipher suites MUST support these extensions, " +
            "and when a client uses these extensions, servers MUST NOT negotiate " +
            "the use of an ECC cipher suite unless they can complete the handshake while respecting the choice " +
            "of curves and compression techniques specified by the client.", interoperabilitySeverity = SeverityLevel.CRITICAL)
    @KeyExchange(supported = KeyExchangeType.ECDH, requiresServerKeyExchMsg = true)
    // TODO: Client test missing
    public void respectChosenCurve(WorkflowRunner runner) {
        runner.replaceSupportedCiphersuites = true;
        Config c = this.getConfig();

        c.setAddEllipticCurveExtension(true);
        c.setAddECPointFormatExtension(true);

        ClientHelloMessage chm = new ClientHelloMessage(c);

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                new SendAction(chm),
                new ReceiveTillAction(new ServerHelloDoneMessage())
        );

        AnnotatedStateContainer container = new AnnotatedStateContainer();
        try {
            List<NamedGroup> groups = context.getConfig().getSiteReport().getSupportedNamedGroups();

            for (NamedGroup i : groups) {
                chm.getExtension(EllipticCurvesExtensionMessage.class).setSupportedGroups(Modifiable.explicit(i.getValue()));
                runner.setStateModifier(s -> {
                    s.addAdditionalTestInfo("Set EC Curve to " + i.name());
                    return null;
                });
                container.addAll(runner.prepare(workflowTrace, c));
            }
        } catch(Exception e) {
            throw new RuntimeException(e);
        }

        runner.execute(container).validateFinal(i -> {
            Validator.executedAsPlanned(i);

            WorkflowTrace trace = i.getWorkflowTrace();
            ECDHEServerKeyExchangeMessage message = trace.getFirstReceivedMessage(ECDHEServerKeyExchangeMessage.class);
            assertNotNull(AssertMsgs.ServerKxNotReceived, message);

            ClientHelloMessage sentChm = trace.getFirstSendMessage(ClientHelloMessage.class);
            byte[] sentEllipticCurve = sentChm.getExtension(EllipticCurvesExtensionMessage.class).getSupportedGroups().getValue();
            byte[] receivedEllipticCurve = message.getNamedGroup().getValue();
            assertArrayEquals("Unexpected named group", sentEllipticCurve, receivedEllipticCurve);
        });
    }
}
