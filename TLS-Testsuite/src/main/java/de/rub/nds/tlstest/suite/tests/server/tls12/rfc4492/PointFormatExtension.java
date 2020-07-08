package de.rub.nds.tlstest.suite.tests.server.tls12.rfc4492;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ECPointFormatExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.ServerTest;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.constants.AssertMsgs;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

@ServerTest
public class PointFormatExtension extends Tls12Test {
    private static final Logger LOGGER = LogManager.getLogger();

    @RFC(number = 4492, section = "5.2. Server Hello Extensions")
    @TlsTest(description = "The Supported Point Formats Extension, when used, MUST contain the value 0 (uncompressed)"+
            " as one of the items in the list of point formats.")
    @KeyExchange(supported = KeyExchangeType.ECDH)
    public void serverSupportsUncompressPointFormat(WorkflowRunner runner) {
        Config c = this.getConfig();

        c.setAddEllipticCurveExtension(true);
        c.setAddECPointFormatExtension(true);

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                new SendAction(new ClientHelloMessage(c)),
                new ReceiveTillAction(new ServerHelloDoneMessage())
        );

        runner.replaceSupportedCiphersuites = true;
        runner.execute(workflowTrace, c).validateFinal(i -> {
            WorkflowTrace trace = i.getWorkflowTrace();
            assertTrue(AssertMsgs.WorkflowNotExecuted, trace.executedAsPlanned());


            ServerHelloMessage message = trace.getFirstReceivedMessage(ServerHelloMessage.class);
            assertNotNull(AssertMsgs.ServerHelloNotReceived, message);

            ECPointFormatExtensionMessage ext = message.getExtension(ECPointFormatExtensionMessage.class);
            assertNotNull("ECPointFormatExtension not received", ext);

            byte[] points = ext.getPointFormats().getValue();
            boolean containsZero = false;
            for (byte b : points) {
                if (b == ECPointFormat.UNCOMPRESSED.getValue()) {
                    containsZero = true;
                    break;
                }
            }
            assertTrue("ECPointFormatExtension does not contain uncompressed format", containsZero);
        });
    }

    @RFC(number = 4492, section = "5.1. Client Hello Extensions")
    @TlsTest(description = "If the Supported Point Formats Extension is indeed sent, "+
            "it MUST contain the value 0 (uncompressed) " +
            "as one of the items in the list of point formats. ")
    @KeyExchange(supported = KeyExchangeType.ECDH)
    public void InvalidPointFormat(WorkflowRunner runner) {
        Config c = this.getConfig();

        c.setAddEllipticCurveExtension(true);
        c.setAddECPointFormatExtension(true);

        ClientHelloMessage chm = new ClientHelloMessage(c);

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                new SendAction(chm),
                new ReceiveAction(new AlertMessage(c))
        );

        chm.getExtension(ECPointFormatExtensionMessage.class)
                .setPointFormats(Modifiable.explicit(new byte[]{(byte) 33}));

        runner.replaceSupportedCiphersuites = true;
        runner.execute(workflowTrace, c).validateFinal(Validator::receivedFatalAlert);
    }
}
