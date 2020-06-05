package de.rub.nds.tlstest.suite.tests.server.tls12.rfc5246;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.ServerTest;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;


@RFC(number = 5246, section = "7.4.7.1")
@ServerTest
public class RSAEncryptedPremasterSecretMessage extends Tls12Test {

    @TlsTest(description = "Client implementations MUST always send the correct version number in PreMasterSecret. " +
            "If ClientHello.client_version is TLS 1.1 or higher, server implementations MUST check " +
            "the version number as described in the note below.\n" +
            "In any case, a TLS server MUST NOT generate an alert if processing an " +
            "RSA-encrypted premaster secret message fails, or the version number " +
            "is not as expected.  Instead, it MUST continue the handshake with a " +
            "randomly generated premaster secret.", securitySeverity = SeverityLevel.CRITICAL)
    @KeyExchange(supported = KeyExchangeType.RSA)
    public void PMWithWrongClientVersion(WorkflowRunner runner) {
        Config c = context.getConfig().createConfig();
        runner.replaceSupportedCiphersuites = true;

        WorkflowTrace workflowTrace = runner.generateWorkflowTraceUntilSendingMessage(WorkflowTraceType.HANDSHAKE, HandshakeMessageType.FINISHED);

        workflowTrace.addTlsActions(
                new SendAction(new FinishedMessage()),
                new ReceiveAction(new AlertMessage())
        );

        runner.setStateModifier(i -> {
            RSAClientKeyExchangeMessage cke = i.getWorkflowTrace().getFirstSendMessage(RSAClientKeyExchangeMessage.class);
            cke.prepareComputations();
            //changes "0x03 0x03" to "0x03 0x02" (TLS1.2 to TLS1.1)
            cke.getComputations().setPremasterSecret(Modifiable.xor(new byte[] {0x00, 0x01}, 0));
            return null;
        });

        runner.execute(workflowTrace, c).validateFinal(Validator::receivedFatalAlert);
    }

    @TlsTest(description = "In any case, a TLS server MUST NOT generate an alert if processing an " +
            "RSA-encrypted premaster secret message fails, or the version number " +
            "is not as expected.  Instead, it MUST continue the handshake with a " +
            "randomly generated premaster secret.")
    @KeyExchange(supported = KeyExchangeType.RSA)
    public void PMWithWrongPKCS1Padding(WorkflowRunner runner) {
        Config c = context.getConfig().createConfig();
        runner.replaceSupportedCiphersuites = true;

        WorkflowTrace workflowTrace = runner.generateWorkflowTraceUntilSendingMessage(WorkflowTraceType.HANDSHAKE, HandshakeMessageType.FINISHED);

        workflowTrace.addTlsActions(
                new SendAction(new FinishedMessage()),
                new ReceiveAction(new AlertMessage())
        );

        runner.setStateModifier(i -> {
            RSAClientKeyExchangeMessage cke = i.getWorkflowTrace().getFirstSendMessage(RSAClientKeyExchangeMessage.class);
            cke.prepareComputations();
            //changes "0x00 0x02 random 0x00" to "0x00 0x01 random 0x00"
            cke.getComputations().setPremasterSecret(Modifiable.xor(new byte[] {0x01}, 1));
            return null;
        });

        runner.execute(workflowTrace, c).validateFinal(Validator::receivedFatalAlert);
    }

}
