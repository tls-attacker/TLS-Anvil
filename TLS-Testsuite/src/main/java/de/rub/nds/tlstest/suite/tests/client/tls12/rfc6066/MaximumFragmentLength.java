/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
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
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.ClientTest;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;

@RFC(number = 6066, section = "4. Maximum Fragment Length Negotiation")
@ClientTest
public class MaximumFragmentLength extends Tls12Test {

    @TlsTest(description = "Similarly, if a client receives a maximum fragment length negotiation " +
            "response that differs from the length it requested, it MUST also abort the handshake with an \"illegal_parameter\" alert.")
    public void invalidMaximumFragmentLength(WorkflowRunner runner) {
        Config c = this.getConfig();
        runner.replaceSelectedCiphersuite = true;

        c.setAddMaxFragmentLengthExtension(true);
        MaxFragmentLengthExtensionMessage maxFLEM = context.getReceivedClientHelloMessage().getExtension(MaxFragmentLengthExtensionMessage.class);
        MaxFragmentLength length = MaxFragmentLength.TWO_11;

        if (maxFLEM != null) {
            if (MaxFragmentLength.getMaxFragmentLength(maxFLEM.getMaxFragmentLength().getValue()[0]) == length) {
                length = MaxFragmentLength.getMaxFragmentLength((byte)(length.getValue() + 1));
            }
        }

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsActions(
                new ReceiveAction(new AlertMessage())
        );

        MaxFragmentLength finalLength = length;
        runner.setStateModifier(i -> {
            WorkflowTrace trace = i.getWorkflowTrace();
            ServerHelloMessage serverHello = trace.getFirstSendMessage(ServerHelloMessage.class);
            serverHello.getExtension(MaxFragmentLengthExtensionMessage.class).setMaxFragmentLength(Modifiable.explicit(new byte[]{finalLength.getValue()}));
            return null;
        });

        runner.execute(workflowTrace, c).validateFinal(i -> {
            Validator.receivedFatalAlert(i);

            WorkflowTrace trace = i.getWorkflowTrace();
            AlertMessage alert = trace.getLastReceivedMessage(AlertMessage.class);
            if (alert == null) return;

            Validator.testAlertDescription(i, AlertDescription.ILLEGAL_PARAMETER, alert);
        });
    }

}
