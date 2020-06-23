package de.rub.nds.tlstest.suite.tests.client.tls12.rfc5246;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.ClientTest;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import static org.junit.Assert.*;

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
        c.setUseAllProvidedRecords(true);
        runner.replaceSelectedCiphersuite = true;

        Record r = new Record();
        r.setContentMessageType(ProtocolMessageType.HANDSHAKE);
        r.setMaxRecordLengthConfig(0);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsActions(
                new ReceiveAction(new AlertMessage())
        );

        runner.setStateModifier(i -> {
            WorkflowTrace trace = i.getWorkflowTrace();
            SendAction action = (SendAction)WorkflowTraceUtil.getFirstSendingActionForMessage(HandshakeMessageType.SERVER_HELLO, trace);
            action.setRecords(r);
            return null;
        });

        runner.execute(workflowTrace, c).validateFinal(Validator::receivedFatalAlert);
    }
}
