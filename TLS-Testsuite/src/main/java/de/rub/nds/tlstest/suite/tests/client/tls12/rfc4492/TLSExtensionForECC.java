package de.rub.nds.tlstest.suite.tests.client.tls12.rfc4492;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ECPointFormatExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EllipticCurvesExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlstest.framework.annotations.ClientTest;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.constants.AssertMsgs;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.List;

import static org.junit.Assert.*;


@RFC(number = 4492, section = "4. TLS Extensions for ECC")
@ClientTest
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

            WorkflowTrace trace = i.getWorkflowTrace();
            AlertMessage message = trace.getFirstReceivedMessage(AlertMessage.class);
            assertNotNull(message);
            assertEquals(AlertLevel.FATAL.getValue(), message.getLevel().getValue().byteValue());
        });
    }

    @TlsTest(description = "The client MUST NOT include these extensions in the ClientHello\n" +
            "   message if it does not propose any ECC cipher suites.", securitySeverity = SeverityLevel.INFORMATIONAL)
    @KeyExchange(provided = KeyExchangeType.DH, supported = KeyExchangeType.RSA)
    public void BothECExtensions_WithoutECCCipher(WorkflowRunner runner) {
        Config c = context.getConfig().createConfig();

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                new ReceiveAction(new ClientHelloMessage(c))
        );

        runner.execute(workflowTrace, c).validateFinal(i -> {
            WorkflowTrace trace = i.getWorkflowTrace();
            assertTrue(AssertMsgs.WorkflowNotExecuted, trace.executedAsPlanned());

            ClientHelloMessage msg = trace.getFirstReceivedMessage(ClientHelloMessage.class);
            assertNotNull(msg);
            byte[] ciphers = msg.getCipherSuites().getValue();
            List<CipherSuite> suites = CipherSuite.getCiphersuites(ciphers);
            suites.removeIf(cs -> !KeyExchangeType.ECDH.compatibleWithCiphersuite(cs));

            if (suites.size() == 0) {
                ECPointFormatExtensionMessage poinfmtExt = msg.getExtension(ECPointFormatExtensionMessage.class);
                EllipticCurvesExtensionMessage ecExt = msg.getExtension(EllipticCurvesExtensionMessage.class);
                assertNull("ECPointFormatExtension should be null", poinfmtExt);
                assertNull("EllipticCurveExtension should be null", ecExt);
            }
        });
    }


    @TlsTest(description = "If the Supported Point Formats Extension is indeed sent, "+
            " it MUST contain the value 0 (uncompressed)" +
            " as one of the items in the list of point formats.")
    @KeyExchange(provided = KeyExchangeType.ECDH)
    public void InvalidPointFormat(WorkflowRunner runner) {
        Config c = context.getConfig().createConfig();

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                new ReceiveAction(new ClientHelloMessage(c))
        );

        runner.execute(workflowTrace, c).validateFinal(i -> {
            WorkflowTrace trace = i.getWorkflowTrace();
            assertTrue(AssertMsgs.WorkflowNotExecuted, trace.executedAsPlanned());

            ClientHelloMessage msg = trace.getFirstReceivedMessage(ClientHelloMessage.class);
            assertNotNull(AssertMsgs.ClientHelloNotReceived, msg);
            ECPointFormatExtensionMessage poinfmtExt = msg.getExtension(ECPointFormatExtensionMessage.class);
            assertNotNull("No ECPointFormatExtension in ClientHello", poinfmtExt);

            boolean contains_zero = false;
            for (byte b : poinfmtExt.getPointFormats().getValue()) {
                if (b == ECPointFormat.UNCOMPRESSED.getValue()) {
                    contains_zero = true;
                    break;
                }
            }
            assertTrue("ECPointFormatExtension does not contain uncompressed format", contains_zero);
        });
    }

}
