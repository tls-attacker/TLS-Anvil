package de.rub.nds.tlstest.suite.tests.server.tls12.rfc7685;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.ServerTest;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import static org.junit.Assert.assertEquals;

@RFC(number = 7685, section = "3")
@ServerTest
public class PaddingExtension extends Tls12Test {
    private static final Logger LOGGER = LogManager.getLogger();


    @TlsTest(description = "The client MUST fill the padding extension completely with zero" +
            "   bytes, although the padding extension_data field may be empty.")
    @KeyExchange(supported = KeyExchangeType.ALL12)
    public void paddingWithNonZero(WorkflowRunner runner) {
        Config config = context.getConfig().createConfig();
        runner.replaceSupportedCiphersuites = true;

        config.setAddPaddingExtension(true);
        config.setDefaultPaddingExtensionBytes(new byte[]{(byte) 0xBA, (byte) 0xBE});

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                new SendAction(new ClientHelloMessage(config)),
                new ReceiveAction(new AlertMessage(config))
        );

        runner.execute(workflowTrace, config).validateFinal(Validator::receivedFatalAlert);
    }
}
