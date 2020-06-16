package de.rub.nds.tlstest.suite.tests.client.tls13.rfc8446;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PSKKeyExchangeModesExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.*;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;

import java.util.ArrayList;

@ClientTest
@RFC(number = 8446, section = "4.2.9 Pre-Shared Key Exchane Modes")
public class PreSharedKeyExchangeModes extends Tls13Test {

    public ConditionEvaluationResult supportsPSKModeExtension() {
        if (context.getReceivedClientHelloMessage().getExtension(PSKKeyExchangeModesExtensionMessage.class) != null) {
            return ConditionEvaluationResult.enabled("");
        }
        return ConditionEvaluationResult.disabled("PSKModeExtension is not supported");
    }

    @TlsTest(description = "The server MUST NOT send a \"psk_key_exchange_modes\" extension.")
    @MethodCondition(method = "supportsPSKModeExtension")
    public void sendPSKModeExtension(WorkflowRunner runner) {
        runner.replaceSelectedCiphersuite = true;

        Config c = this.getConfig();
        c.setAddPSKKeyExchangeModesExtension(true);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsActions(new ReceiveAction(new AlertMessage()));

        runner.setStateModifier(i -> {
            WorkflowTrace trace = i.getWorkflowTrace();
            ServerHelloMessage sh = trace.getFirstSendMessage(ServerHelloMessage.class);
            PSKKeyExchangeModesExtensionMessage ext = new PSKKeyExchangeModesExtensionMessage();
            ext.setExtensionBytes(Modifiable.explicit(context.getReceivedClientHelloMessage().getExtension(PSKKeyExchangeModesExtensionMessage.class).getExtensionBytes().getValue()));

            sh.addExtension(ext);
            return null;
        });

        runner.execute(workflowTrace, c).validateFinal(Validator::receivedFatalAlert);
    }

}
