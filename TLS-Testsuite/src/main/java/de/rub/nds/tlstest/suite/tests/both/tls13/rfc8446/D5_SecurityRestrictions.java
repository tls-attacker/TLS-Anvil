/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.both.tls13.rfc8446;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.annotations.categories.Interoperability;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.constants.TestEndpointType;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;


public class D5_SecurityRestrictions extends Tls13Test {

    @TlsTest(description = "Implementations MUST NOT send any records with a " +
            "version less than 0x0300. Implementations SHOULD NOT accept any " +
            "records with a version less than 0x0300 (but may inadvertently " +
            "do so if the record version number is ignored completely).")
    @RFC(number = 8446, section = "D.5. Security Restrictions Related to Backward Compatibility")
    @Interoperability(SeverityLevel.MEDIUM)
    public void invalidRecordVersion_ssl30(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);

        Record record = new Record();
        record.setProtocolVersion(Modifiable.explicit(new byte[]{0x02, (byte)0x03}));

        WorkflowTrace trace;
        if (context.getConfig().getTestEndpointMode() == TestEndpointType.CLIENT) {
            trace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        } else {
            trace = new WorkflowTrace();
            trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
        }

        trace.addTlsActions(
                new ReceiveAction(new AlertMessage())
        );

        SendAction action;
        action = trace.getFirstAction(SendAction.class);
        action.setRecords(record);

        runner.execute(trace, config).validateFinal(Validator::receivedFatalAlert);
    }
}
