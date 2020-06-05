package de.rub.nds.tlstest.suite.tests.server.tls12.rfc4492;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EllipticCurvesExtensionMessage;
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
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.List;

import static org.junit.Assert.*;


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

        runner.execute(workflowTrace, config).validateFinal(Validator::receivedFatalAlert);
    }

    @RFC(number = 4492, section = "4. TLS Extensions for ECC")
    @TlsTest(description = "The client MUST NOT include these extensions in the ClientHello\n" +
            "   message if it does not propose any ECC cipher suites.", securitySeverity = SeverityLevel.INFORMATIONAL)
    @KeyExchange(provided = KeyExchangeType.RSA, supported = KeyExchangeType.DH)
    public void BothECExtensions_WithoutECCCipher(WorkflowRunner runner) {
        Config c = context.getConfig().createConfig();

        c.setAddEllipticCurveExtension(true);
        c.setAddECPointFormatExtension(true);

        execute(runner, c);
    }

    @RFC(number = 4492, section = "4. TLS Extensions for ECC")
    @TlsTest(description = "The client MUST NOT include these extensions in the ClientHello\n" +
            "   message if it does not propose any ECC cipher suites.")
    @KeyExchange(provided = KeyExchangeType.RSA, supported = KeyExchangeType.DH)
    public void ECExtension_WithoutECCCipher(WorkflowRunner runner) {
        Config c = context.getConfig().createConfig();

        c.setAddEllipticCurveExtension(true);
        c.setAddECPointFormatExtension(false);

        execute(runner, c);
    }

    @RFC(number = 4492, section = "4. TLS Extensions for ECC")
    @TlsTest(description = "The client MUST NOT include these extensions in the ClientHello\n" +
            "   message if it does not propose any ECC cipher suites.")
    @KeyExchange(provided = KeyExchangeType.RSA, supported = KeyExchangeType.DH)
    public void ECPointFormatExtension_WithoutECCCipher(WorkflowRunner runner) {
        Config c = context.getConfig().createConfig();

        c.setAddEllipticCurveExtension(false);
        c.setAddECPointFormatExtension(true);

        execute(runner, c);
    }


    @RFC(number = 4492, section = "5.1. Client Hello Extensions")
    @TlsTest(description = "If a server does not understand the Supported Elliptic Curves Extension, " +
            "does not understand the Supported Point Formats Extension, or is unable to complete the ECC handshake " +
            "while restricting itself to the enumerated curves and point formats, " +
            "it MUST NOT negotiate the use of an ECC cipher suite.", interoperabilitySeverity = SeverityLevel.LOW)
    @KeyExchange(provided = KeyExchangeType.ECDH)
    public void InvalidEllipticCurve(WorkflowRunner runner) {
        Config c = context.getConfig().createConfig();
        runner.replaceSupportedCiphersuites = true;

        c.setAddEllipticCurveExtension(true);
        c.setAddECPointFormatExtension(true);

        ClientHelloMessage chm = new ClientHelloMessage(c);

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                new SendAction(chm),
                new ReceiveAction(new AlertMessage(c))
        );

        chm.getExtension(EllipticCurvesExtensionMessage.class).setSupportedGroups(Modifiable.explicit(new byte[]{(byte) 123, 124}));

        runner.execute(workflowTrace, c).validateFinal(Validator::receivedFatalAlert);
    }

    @RFC(number = 4492, section = "5.1. Client Hello Extensions")
    @TlsTest(description = "If a server does not understand the Supported Elliptic Curves Extension, " +
            "does not understand the Supported Point Formats Extension, or is unable to complete the ECC handshake " +
            "while restricting itself to the enumerated curves and point formats, " +
            "it MUST NOT negotiate the use of an ECC cipher suite.", interoperabilitySeverity = SeverityLevel.CRITICAL)
    @KeyExchange(provided = KeyExchangeType.ECDH, supported = KeyExchangeType.ALL12)
    public void InvalidEllipticCurve_WithNonECCCiphersuite(WorkflowRunner runner) {
        runner.appendEachSupportedCiphersuiteToClientSupported = true;
        Config c = context.getConfig().createConfig();

        c.setAddEllipticCurveExtension(true);
        c.setAddECPointFormatExtension(true);
        List<CipherSuite> cipherSuiteList = CipherSuite.getImplemented();
        cipherSuiteList.removeIf(i -> KeyExchangeType.forCipherSuite(i) != KeyExchangeType.ECDH);

        c.setDefaultClientSupportedCiphersuites(cipherSuiteList);

        ClientHelloMessage chm = new ClientHelloMessage(c);

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                new SendAction(chm),
                new ReceiveTillAction(new ServerHelloDoneMessage())
        );

        chm.getExtension(EllipticCurvesExtensionMessage.class).setSupportedGroups(Modifiable.explicit(new byte[]{(byte) 123, 124}));

        runner.execute(workflowTrace, c).validateFinal(i -> {
            assertTrue(AssertMsgs.WorkflowNotExecuted, i.getWorkflowTrace().executedAsPlanned());

            WorkflowTrace trace = i.getWorkflowTrace();
            ServerHelloMessage message = trace.getFirstReceivedMessage(ServerHelloMessage.class);
            assertNotNull(AssertMsgs.ServerHelloNotReceived, message);
            assertArrayEquals(AssertMsgs.UnexpectedCipherSuite, i.getInspectedCipherSuite().getByteValue(), message.getSelectedCipherSuite().getValue());
        });
    }



}
