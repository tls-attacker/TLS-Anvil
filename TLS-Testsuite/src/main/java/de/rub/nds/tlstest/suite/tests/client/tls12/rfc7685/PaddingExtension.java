package de.rub.nds.tlstest.suite.tests.client.tls12.rfc7685;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PaddingExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlstest.framework.annotations.ClientTest;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.constants.AssertMsgs;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotNull;

@RFC(number = 7685, section = "3")
@ClientTest
public class PaddingExtension extends Tls12Test {

    @TlsTest(description = "The client MUST fill the padding extension completely with zero\n" +
            "   bytes, although the padding extension_data field may be empty.")
    @KeyExchange(supported = KeyExchangeType.ALL12)
    public void paddingWithNonZero(WorkflowRunner runner) {
        Config config = context.getConfig().createConfig();

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                new ReceiveAction(new ClientHelloMessage(config))
        );

        runner.execute(workflowTrace, config).validateFinal(i -> {
            WorkflowTrace trace = i.getWorkflowTrace();
            ClientHelloMessage msg = trace.getFirstReceivedMessage(ClientHelloMessage.class);
            assertNotNull(AssertMsgs.ClientHelloNotReceived, msg);

            PaddingExtensionMessage paddingExt = msg.getExtension(PaddingExtensionMessage.class);
            if (paddingExt == null) {
                return;
            }

            byte[] receivedPaddingExt = paddingExt.getPaddingBytes().getValue();
            byte[] expected = new byte[receivedPaddingExt.length];
            assertArrayEquals("Padding extension padding bytes not zero", expected, receivedPaddingExt);
        });

    }

}
