package de.rub.nds.tlstest.suite.tests.tls12.server.rfc4492;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.ServerTest;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import static org.junit.Assert.*;


@RFC(number = 4492, section = "4. TLS Extensions for ECC")
@ServerTest
public class TLSExtensionForECC extends Tls12Test {
    private static final Logger LOGGER = LogManager.getLogger();

    private void execute(WorkflowRunner runner, Config config) {
        runner.replaceSupportedCiphersuites = true;

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                new SendAction(new ClientHelloMessage(config)),
                new ReceiveAction(new AlertMessage(config))
        );

        runner.execute(workflowTrace, config).validateFinal(i -> {
            assertTrue(i.getWorkflowTrace().executedAsPlanned());

            AlertMessage message = WorkflowTraceUtil.getFirstReceivedMessage(AlertMessage.class, i.getWorkflowTrace());
            assertNotNull(message);
            assertEquals(AlertLevel.FATAL.getValue(), message.getLevel().getValue().byteValue());
        });
    }

    @TlsTest(description = "The client MUST NOT include these extensions in the ClientHello\n" +
            "   message if it does not propose any ECC cipher suites.")
    @KeyExchange(provided = KeyExchangeType.RSA, supported = KeyExchangeType.DH )
    public void BothECExtensions_WithoutECCCipher(WorkflowRunner runner) {
        Config c = context.getConfig().createConfig();

        c.setAddEllipticCurveExtension(true);
        c.setAddECPointFormatExtension(true);

        execute(runner, c);
    }

    @TlsTest(description = "The client MUST NOT include these extensions in the ClientHello\n" +
            "   message if it does not propose any ECC cipher suites.")
    @KeyExchange(provided = KeyExchangeType.RSA, supported = KeyExchangeType.DH )
    public void ECExtension_WithoutECCCipher(WorkflowRunner runner) {
        Config c = context.getConfig().createConfig();

        c.setAddEllipticCurveExtension(true);
        c.setAddECPointFormatExtension(false);

        execute(runner, c);
    }

    @TlsTest(description = "The client MUST NOT include these extensions in the ClientHello\n" +
            "   message if it does not propose any ECC cipher suites.")
    @KeyExchange(provided = KeyExchangeType.RSA, supported = KeyExchangeType.DH )
    public void ECPointFormatExtension_WithoutECCCipher(WorkflowRunner runner) {
        Config c = context.getConfig().createConfig();

        c.setAddEllipticCurveExtension(false);
        c.setAddECPointFormatExtension(true);

        execute(runner, c);
    }
}
