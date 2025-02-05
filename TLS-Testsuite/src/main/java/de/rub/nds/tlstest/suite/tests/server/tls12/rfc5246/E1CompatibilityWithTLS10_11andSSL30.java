/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.server.tls12.rfc5246;

import static org.junit.Assert.assertArrayEquals;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.ExcludeParameter;
import de.rub.nds.anvilcore.annotation.MethodCondition;
import de.rub.nds.anvilcore.annotation.ServerTest;
import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.teststate.AnvilTestCase;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
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
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.derivationParameter.ProtocolVersionDerivation;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;

@ServerTest
public class E1CompatibilityWithTLS10_11andSSL30 extends Tls12Test {

    @AnvilTest(id = "5246-1dbRcCn9si")
    public void versionGreaterThanSupportedByServer(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);

        ModifiableByteArray protocolVersionSend = Modifiable.explicit(new byte[] {0x03, 0x0F});

        ClientHelloMessage chm = new ClientHelloMessage(c);
        chm.setProtocolVersion(protocolVersionSend);
        SendAction sendAction = new SendAction(chm);

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                sendAction, new ReceiveTillAction(new ServerHelloDoneMessage()));

        State state = runner.execute(workflowTrace, c);

        WorkflowTrace trace = state.getWorkflowTrace();
        Validator.executedAsPlanned(state, testCase);

        ServerHelloMessage msg = trace.getFirstReceivedMessage(ServerHelloMessage.class);
        assertArrayEquals(
                "Invalid ProtocolVersion negotiated",
                ProtocolVersion.TLS12.getValue(),
                msg.getProtocolVersion().getValue());
    }

    public ConditionEvaluationResult doesSupportLegacyVersions() {
        Set<ProtocolVersion> versions = context.getFeatureExtractionResult().getSupportedVersions();
        if (!versions.contains(ProtocolVersion.SSL3)
                || !versions.contains(ProtocolVersion.TLS10)
                || !versions.contains(ProtocolVersion.TLS11)) {
            return ConditionEvaluationResult.enabled("");
        }
        return ConditionEvaluationResult.disabled("Does not support legacy versions");
    }

    @AnvilTest(id = "5246-cBgzhL56ow")
    @MethodCondition(method = "doesSupportLegacyVersions")
    public void versionLowerThanSupportedByServer(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);

        ProtocolVersion version = ProtocolVersion.SSL3;
        Set<ProtocolVersion> versions = context.getFeatureExtractionResult().getSupportedVersions();
        if (!versions.contains(ProtocolVersion.TLS11)) {
            version = ProtocolVersion.TLS11;
        } else if (!versions.contains(ProtocolVersion.TLS10)) {
            version = ProtocolVersion.TLS10;
        }

        c.setSupportedVersions(version);
        c.setHighestProtocolVersion(version);

        Record record = new Record();
        record.setProtocolVersion(Modifiable.explicit(version.getValue()));
        SendAction cha = new SendAction(new ClientHelloMessage(c));
        cha.setConfiguredRecords(List.of(record));

        WorkflowTrace trace = new WorkflowTrace();
        trace.addTlsActions(cha, new ReceiveAction(new AlertMessage()));

        State state = runner.execute(trace, c);

        Validator.receivedFatalAlert(state, testCase);

        AlertMessage alert = state.getWorkflowTrace().getFirstReceivedMessage(AlertMessage.class);
        Validator.testAlertDescription(state, testCase, AlertDescription.PROTOCOL_VERSION, alert);
    }

    @AnvilTest(id = "5246-YLok6XJr7R")
    @ExcludeParameter("RECORD_LENGTH")
    public void acceptAnyRecordVersionNumber(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);

        Record record = new Record();
        record.setProtocolVersion(Modifiable.explicit(new byte[] {0x03, 0x05}));
        SendAction sendAction = new SendAction(new ClientHelloMessage(c));
        sendAction.setConfiguredRecords(List.of(record));

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                sendAction, new ReceiveTillAction(new ServerHelloDoneMessage()));

        State state = runner.execute(workflowTrace, c);
        Validator.executedAsPlanned(state, testCase);
    }

    public List<DerivationParameter<Config, byte[]>> getInvalidHighRecordVersion(
            DerivationScope scope) {
        List<DerivationParameter<Config, byte[]>> parameterValues = new LinkedList<>();
        parameterValues.add(new ProtocolVersionDerivation(new byte[] {0x04, 0x00}));
        parameterValues.add(new ProtocolVersionDerivation(new byte[] {0x04, 0x03}));
        parameterValues.add(new ProtocolVersionDerivation(new byte[] {0x04, 0x0F}));
        return parameterValues;
    }
}
