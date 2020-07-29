package de.rub.nds.tlstest.suite.tests.client.tls12.rfc5246;

import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendDynamicServerKeyExchangeAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.*;
import de.rub.nds.tlstest.framework.constants.AssertMsgs;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;

import static org.junit.Assert.assertTrue;


@RFC(number = 5246, section = "E.1. Compatibility with TLS 1.0/1.1 and SSL 3.0")
@ClientTest
public class E1CompatibilityWithTLS10_11andSSL30 extends Tls12Test {

    @TlsTest(description = "If the version chosen by the server is not supported by the client "+
            "(or not acceptable), the client MUST send a \"protocol_version\" alert "+
            "message and close the connection.", interoperabilitySeverity = SeverityLevel.CRITICAL)
    public void selectUnsupportedVersion(WorkflowRunner runner) {
        Config c = this.getConfig();
        runner.replaceSelectedCiphersuite = true;

        ModifiableByteArray protocolVersionSend = Modifiable.explicit(new byte[]{0x03, 0x0F});

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsActions(
                new ReceiveAction(new AlertMessage())
        );

        runner.setStateModifier(i -> {
            i.getWorkflowTrace().getFirstSendMessage(ServerHelloMessage.class)
                    .setProtocolVersion(protocolVersionSend);
            return null;
        });

        runner.execute(workflowTrace, c).validateFinal(i -> {
            Validator.receivedFatalAlert(i);
            WorkflowTrace trace = i.getWorkflowTrace();

            AlertMessage msg = trace.getFirstReceivedMessage(AlertMessage.class);
            Validator.testAlertDescription(i, AlertDescription.PROTOCOL_VERSION, msg);
        });
    }
}
