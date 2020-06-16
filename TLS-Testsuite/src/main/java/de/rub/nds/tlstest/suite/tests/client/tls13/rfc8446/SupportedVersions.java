package de.rub.nds.tlstest.suite.tests.client.tls13.rfc8446;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SupportedVersionsExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.*;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.Assert.*;

@RFC(number = 8446, section = "4.2.1 Supported Versions")
@ClientTest
public class SupportedVersions extends Tls13Test {
    public ConditionEvaluationResult supportsTls12() {
        if (context.getConfig().getSiteReport().getVersions().contains(ProtocolVersion.TLS12)) {
            return ConditionEvaluationResult.enabled("");
        }
        return ConditionEvaluationResult.disabled("TLS 1.2 is not supported by the server.");
    }

    @TlsTest(description = "If this extension is present, clients MUST ignore the " +
            "ServerHello.legacy_version value and MUST use " +
            "only the \"supported_versions\" extension to determine the selected version.")
    public void invalidLegacyVersion(WorkflowRunner runner) {
        runner.replaceSelectedCiphersuite = true;

        Config c = this.getConfig();
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        runner.setStateModifier(i -> {
            i.getWorkflowTrace().getFirstSendMessage(ServerHelloMessage.class).setProtocolVersion(Modifiable.explicit(new byte[]{0x05, 0x05}));
            return null;
        });

        runner.execute(workflowTrace, c).validateFinal(Validator::executedAsPlanned);
    }

    @TlsTest(description = "If the \"supported_versions\" extension in the ServerHello " +
            "contains a version not offered by the client or contains a version " +
            "prior to TLS 1.3, the client MUST abort the " +
            "handshake with an \"illegal_parameter\" alert.")
    @MethodCondition(method = "supportsTls12")
    public void selectOlderTlsVersion(WorkflowRunner runner) {
        runner.replaceSelectedCiphersuite = true;

        Config c = this.getConfig();
        c.setEnforceSettings(true);
        WorkflowTrace workflowTrace = runner.generateWorkflowTraceUntilReceivingMessage(WorkflowTraceType.HANDSHAKE, ProtocolMessageType.CHANGE_CIPHER_SPEC);
        workflowTrace.addTlsActions(
                new ReceiveAction(new AlertMessage())
        );
        runner.setStateModifier(i -> {
            i.getWorkflowTrace().getFirstSendMessage(ServerHelloMessage.class)
                    .getExtension(SupportedVersionsExtensionMessage.class)
                    .setSupportedVersions(Modifiable.explicit(new byte[]{0x03, 0x03}));
            return null;
        });

        runner.execute(workflowTrace, c).validateFinal(i -> {
            Validator.receivedFatalAlert(i);

            AlertMessage msg = i.getWorkflowTrace().getFirstReceivedMessage(AlertMessage.class);
            if (msg == null) return;
            Validator.testAlertDescription(i, AlertDescription.ILLEGAL_PARAMETER, msg);
        });
    }
}
