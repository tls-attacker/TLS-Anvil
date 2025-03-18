package de.rub.nds.tlstest.suite.util;

import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import java.util.List;

public abstract class SharedModifiedRecords {

    public static SendAction getZeroLengthRecordAction() {
        ApplicationMessage appMsg = new ApplicationMessage();
        Record zeroLengthRecord = new Record();
        zeroLengthRecord.setContentMessageType(ProtocolMessageType.APPLICATION_DATA);
        zeroLengthRecord.setMaxRecordLengthConfig(0);
        SendAction sendAction = new SendAction(appMsg);
        // send prepared record and second record carrying actual application data to check if SQN
        // is correct
        sendAction.setConfiguredRecords(List.of(zeroLengthRecord, new Record()));
        return sendAction;
    }
}
