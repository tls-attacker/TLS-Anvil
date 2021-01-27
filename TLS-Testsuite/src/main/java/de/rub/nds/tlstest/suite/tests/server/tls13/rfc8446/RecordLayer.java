/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.server.tls13.rfc8446;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.ScopeLimitations;
import de.rub.nds.tlstest.framework.annotations.ServerTest;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.annotations.categories.AlertCategory;
import de.rub.nds.tlstest.framework.annotations.categories.ComplianceCategory;
import de.rub.nds.tlstest.framework.annotations.categories.CryptoCategory;
import de.rub.nds.tlstest.framework.annotations.categories.DeprecatedFeatureCategory;
import de.rub.nds.tlstest.framework.annotations.categories.HandshakeCategory;
import de.rub.nds.tlstest.framework.annotations.categories.InteroperabilityCategory;
import de.rub.nds.tlstest.framework.annotations.categories.MessageStructureCategory;
import de.rub.nds.tlstest.framework.annotations.categories.RecordLayerCategory;
import de.rub.nds.tlstest.framework.annotations.categories.SecurityCategory;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.DerivationType;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@ServerTest
@RFC(number = 8446, section = "5.1. Record Layer")
public class RecordLayer extends Tls13Test {

    @TlsTest(description = "Implementations MUST NOT send "
            + "zero-length fragments of Handshake types, even "
            + "if those fragments contain padding.")
    @InteroperabilityCategory(SeverityLevel.HIGH)
    @RecordLayerCategory(SeverityLevel.LOW)
    @ComplianceCategory(SeverityLevel.HIGH)
    @AlertCategory(SeverityLevel.MEDIUM)
    public void zeroLengthRecord_CH(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        c.setUseAllProvidedRecords(true);

        SendAction clientHello = new SendAction(new ClientHelloMessage(c));
        Record record = new Record();
        record.setMaxRecordLengthConfig(0);
        clientHello.setRecords(record);

        WorkflowTrace trace = new WorkflowTrace();
        trace.addTlsActions(
                clientHello,
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(trace, c).validateFinal(Validator::receivedFatalAlert);
    }

    @TlsTest(description = "Implementations MUST NOT send "
            + "zero-length fragments of Handshake types, even "
            + "if those fragments contain padding.")
    @InteroperabilityCategory(SeverityLevel.HIGH)
    @RecordLayerCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    @AlertCategory(SeverityLevel.MEDIUM)
    public void zeroLengthRecord_Finished(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        c.setUseAllProvidedRecords(true);

        Record record = new Record();
        record.setMaxRecordLengthConfig(0);
        WorkflowTrace trace = runner.generateWorkflowTraceUntilSendingMessage(WorkflowTraceType.HANDSHAKE, HandshakeMessageType.FINISHED);
        trace.addTlsActions(
                new SendAction(new FinishedMessage()),
                new ReceiveAction(new AlertMessage())
        );

        SendAction finished = (SendAction) WorkflowTraceUtil.getFirstSendingActionForMessage(HandshakeMessageType.FINISHED, trace);
        finished.setRecords(record);

        runner.execute(trace, c).validateFinal(Validator::receivedFatalAlert);
    }

    @TlsTest(description = "Handshake messages MUST NOT be interleaved "
            + "with other record types.")
    @ScopeLimitations(DerivationType.INCLUDE_CHANGE_CIPHER_SPEC)
    @InteroperabilityCategory(SeverityLevel.HIGH)
    @RecordLayerCategory(SeverityLevel.LOW)
    @ComplianceCategory(SeverityLevel.HIGH)
    @AlertCategory(SeverityLevel.MEDIUM)
    public void interleaveRecords(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        c.setCreateIndividualRecords(false);
        c.setFlushOnMessageTypeChange(false);

        WorkflowTrace trace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        trace.addTlsAction(new ReceiveAction(new AlertMessage()));

        runner.execute(trace, c).validateFinal(Validator::receivedFatalAlert);
    }
}
