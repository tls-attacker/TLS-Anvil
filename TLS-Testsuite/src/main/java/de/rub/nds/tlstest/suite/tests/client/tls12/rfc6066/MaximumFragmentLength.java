package de.rub.nds.tlstest.suite.tests.client.tls12.rfc6066;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.MaxFragmentLength;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.MaxFragmentLengthExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendDynamicServerCertificateAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendDynamicServerKeyExchangeAction;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.ServerTest;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;

@RFC(number = 6066, section = "4. Maximum Fragment Length Negotiation")
@ServerTest
public class MaximumFragmentLength extends Tls12Test {

    @TlsTest(description = "Similarly, if a client receives a maximum fragment length negotiation " +
            "response that differs from the length it requested, it MUST also abort the handshake with an \"illegal_parameter\" alert.")
    @KeyExchange(supported = KeyExchangeType.ALL12)
    public void invalidMaximumFragmentLength(WorkflowRunner runner) {
        Config c = this.getConfig();
        runner.replaceSupportedCiphersuites = true;

        c.setAddMaxFragmentLengthExtension(true);
        ServerHelloMessage serverHello = new ServerHelloMessage(c);
        MaxFragmentLengthExtensionMessage maxFLEM = context.getReceivedClientHelloMessage().getExtension(MaxFragmentLengthExtensionMessage.class);
        MaxFragmentLength length = MaxFragmentLength.TWO_11;

        if (maxFLEM != null) {
            if (MaxFragmentLength.getMaxFragmentLength(maxFLEM.getMaxFragmentLength().getValue()[0]) == length) {
                length = MaxFragmentLength.getMaxFragmentLength((byte)(length.getValue() + 1));
            }
        }

        serverHello.getExtension(MaxFragmentLengthExtensionMessage.class).setMaxFragmentLength(Modifiable.explicit(new byte[]{length.getValue()}));

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                new ReceiveAction(serverHello),
                new SendAction(serverHello),
                new SendDynamicServerCertificateAction(),
                new SendDynamicServerKeyExchangeAction(),
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(workflowTrace, c).validateFinal(i -> {
            Validator.receivedFatalAlert(i);

            WorkflowTrace trace = i.getWorkflowTrace();
            AlertMessage alert = trace.getLastReceivedMessage(AlertMessage.class);
            Validator.testAlertDescription(i, AlertDescription.ILLEGAL_PARAMETER, alert);
        });
    }

}
