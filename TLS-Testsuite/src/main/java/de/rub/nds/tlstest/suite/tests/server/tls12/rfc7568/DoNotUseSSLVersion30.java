/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.server.tls12.rfc7568;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.anvilcore.annotation.*;
import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.teststate.AnvilTestCase;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.constants.AssertMsgs;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.derivationParameter.ProtocolVersionDerivation;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import java.util.LinkedList;
import java.util.List;

@ServerTest
public class DoNotUseSSLVersion30 extends Tls12Test {

    @AnvilTest(id = "7568-SxJGaYDNfG")
    public void sendClientHelloVersion0300(AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);

        ClientHelloMessage clientHelloMessage = new ClientHelloMessage(config);
        clientHelloMessage.setProtocolVersion(Modifiable.explicit(new byte[] {0x03, 0x00}));

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                new SendAction(clientHelloMessage), new ReceiveAction(new AlertMessage()));

        State state = runner.execute(workflowTrace, config);

        WorkflowTrace trace = state.getWorkflowTrace();
        Validator.receivedFatalAlert(state, testCase);
        AlertMessage msg = trace.getFirstReceivedMessage(AlertMessage.class);
        Validator.testAlertDescription(state, testCase, AlertDescription.PROTOCOL_VERSION, msg);
    }

    public List<DerivationParameter<Config, byte[]>> get03ProtocolVersions(DerivationScope scope) {
        List<DerivationParameter<Config, byte[]>> parameterValues = new LinkedList<>();
        for (byte i : new byte[] {0x00, 0x01, 0x02, 0x04, 0x05, (byte) 0xff}) {
            parameterValues.add(new ProtocolVersionDerivation(new byte[] {0x03, i}));
        }
        return parameterValues;
    }

    @AnvilTest(id = "7568-4aw1KUVQi9")
    @IncludeParameter("PROTOCOL_VERSION")
    // we can't retain the version across all records if we don't know how
    // many are required
    @ExcludeParameter("RECORD_LENGTH")
    @ExplicitValues(affectedIdentifiers = "PROTOCOL_VERSION", methods = "get03ProtocolVersions")
    @ManualConfig(identifiers = "PROTOCOL_VERSION")
    public void sendClientHelloVersion0300DifferentRecordVersion(
            AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);
        byte[] protocolVersionBytes =
                parameterCombination
                        .getParameter(ProtocolVersionDerivation.class)
                        .getSelectedValue();

        Record record = new Record();
        record.setProtocolVersion(Modifiable.explicit(protocolVersionBytes));
        ClientHelloMessage clientHelloMessage = new ClientHelloMessage(config);
        clientHelloMessage.setProtocolVersion(Modifiable.explicit(new byte[] {0x03, 0x00}));

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                new SendAction(clientHelloMessage), new ReceiveAction(new AlertMessage()));

        State state = runner.execute(workflowTrace, config);

        WorkflowTrace trace = state.getWorkflowTrace();
        Validator.receivedFatalAlert(state, testCase);
        AlertMessage msg = trace.getFirstReceivedMessage(AlertMessage.class);
        Validator.testAlertDescription(state, testCase, AlertDescription.PROTOCOL_VERSION, msg);
    }

    @AnvilTest(id = "7568-6CdJpT15w2")
    @IncludeParameter("PROTOCOL_VERSION")
    // we can't retain the version across all records if we don't know how
    // many are required
    @ExcludeParameter("RECORD_LENGTH")
    @ExplicitValues(affectedIdentifiers = "PROTOCOL_VERSION", methods = "get03ProtocolVersions")
    @ManualConfig(identifiers = "PROTOCOL_VERSION")
    public void sendClientHelloVersion0300RecordVersion(
            AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);
        byte[] protocolVersionBytes =
                parameterCombination
                        .getParameter(ProtocolVersionDerivation.class)
                        .getSelectedValue();

        Record record = new Record();
        record.setProtocolVersion(Modifiable.explicit(protocolVersionBytes));
        ClientHelloMessage clientHelloMessage = new ClientHelloMessage(config);

        SendAction sendAction = new SendAction(clientHelloMessage);
        sendAction.setConfiguredRecords(List.of(record));

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                sendAction, new ReceiveTillAction(new ServerHelloDoneMessage()));

        State state = runner.execute(workflowTrace, config);

        WorkflowTrace trace = state.getWorkflowTrace();
        Validator.executedAsPlanned(state, testCase);

        ServerHelloMessage shm = trace.getFirstReceivedMessage(ServerHelloMessage.class);
        assertNotNull(shm, AssertMsgs.SERVER_HELLO_NOT_RECEIVED);

        assertArrayEquals(
                new byte[] {0x03, 0x03},
                shm.getProtocolVersion().getValue(),
                "Invalid TLS version negotiated");
    }
}
