package de.rub.nds.tlstest.suite.tests.client.tls12.rfc5246;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.ClientTest;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;

@RFC(number = 5264, section = "6.2.1 Fragmentation")
@ClientTest
public class Fragmentation extends Tls12Test {

    @TlsTest(description = "Implementations MUST NOT send zero-length fragments of Handshake, " +
            "Alert, or ChangeCipherSpec content types. Zero-length fragments of " +
            "Application data MAY be sent as they are potentially useful as a " +
            "traffic analysis countermeasure.")
    @KeyExchange(supported = KeyExchangeType.ALL12)
    public void sendZeroLengthRecord_SH(WorkflowRunner runner) {
        Config c = this.getConfig();
        c.setDefaultClientSupportedCiphersuites(CipherSuite.getImplemented());
        c.setUseAllProvidedRecords(true);
        runner.replaceSupportedCiphersuites = true;

        Record r = new Record();
        r.setContentMessageType(ProtocolMessageType.HANDSHAKE);
        r.setMaxRecordLengthConfig(0);
        SendAction sendAction = new SendAction(new ServerHelloMessage(c));
        sendAction.setRecords(r);

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                sendAction,
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(workflowTrace, c).validateFinal(Validator::receivedFatalAlert);
    }

    @TlsTest(description = "Implementations MUST NOT send zero-length fragments of Handshake, " +
            "Alert, or ChangeCipherSpec content types. Zero-length fragments of " +
            "Application data MAY be sent as they are potentially useful as a " +
            "traffic analysis countermeasure.")
    @KeyExchange(supported = KeyExchangeType.ALL12)
    public void sendZeroLengthRecord_Alert(WorkflowRunner runner) {
        Config c = this.getConfig();
        c.setDefaultClientSupportedCiphersuites(CipherSuite.getImplemented());
        c.setUseAllProvidedRecords(true);
        runner.replaceSupportedCiphersuites = true;

        AlertMessage alertMsg = new AlertMessage(c);
        alertMsg.setLevel(Modifiable.explicit(AlertLevel.WARNING.getValue()));
        alertMsg.setDescription(Modifiable.explicit(AlertDescription.CLOSE_NOTIFY.getValue()));

        Record r = new Record();
        r.setContentMessageType(ProtocolMessageType.ALERT);
        r.setMaxRecordLengthConfig(0);
        SendAction sendAction = new SendAction(alertMsg);
        sendAction.setRecords(r);

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                new ReceiveAction(new ClientHelloMessage(c)),
                sendAction,
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(workflowTrace, c).validateFinal(Validator::receivedFatalAlert);
    }
}
