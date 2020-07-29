package de.rub.nds.tlstest.suite.tests.server.tls12.rfc5246;

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
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.annotations.MethodCondition;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.ServerTest;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.constants.AssertMsgs;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;

import java.util.List;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;


@RFC(number = 5246, section = "E.1. Compatibility with TLS 1.0/1.1 and SSL 3.0")
@ServerTest
public class E1CompatibilityWithTLS10_11andSSL30 extends Tls12Test {

    @TlsTest(description = "If a TLS server receives a ClientHello containing a version number " +
            "greater than the highest version supported by the server, it MUST " +
            "reply according to the highest version supported by the server.", interoperabilitySeverity = SeverityLevel.CRITICAL)
    public void versionGreaterThanSupportedByServer(WorkflowRunner runner) {
        Config c = this.getConfig();
        runner.replaceSupportedCiphersuites = true;

        ModifiableByteArray protocolVersionSend = Modifiable.explicit(new byte[]{0x03, 0x0F});

        ClientHelloMessage chm = new ClientHelloMessage(c);
        chm.setProtocolVersion(protocolVersionSend);
        SendAction sendAction = new SendAction(chm);

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                sendAction,
                new ReceiveTillAction(new ServerHelloDoneMessage())
        );

        runner.execute(workflowTrace, c).validateFinal(i -> {
            WorkflowTrace trace = i.getWorkflowTrace();
            Validator.executedAsPlanned(i);

            ServerHelloMessage msg = trace.getFirstReceivedMessage(ServerHelloMessage.class);
            assertArrayEquals("Invalid ProtocolVersion negotiated",
                    ProtocolVersion.TLS12.getValue(),
                    msg.getProtocolVersion().getValue()
            );
        });
    }

    public ConditionEvaluationResult doesSupportLegacyVersions() {
        List<ProtocolVersion> versions = context.getConfig().getSiteReport().getVersions();
        if (!versions.contains(ProtocolVersion.SSL3) || !versions.contains(ProtocolVersion.TLS10) || !versions.contains(ProtocolVersion.TLS11)) {
            return ConditionEvaluationResult.enabled("");
        }
        return ConditionEvaluationResult.disabled("Does not support legacy versions");
    }

    @TlsTest(description = "If server supports (or is willing to use) only " +
            "versions greater than client_version, it MUST send a " +
            "\"protocol_version\" alert message and close the connection.", interoperabilitySeverity = SeverityLevel.LOW)
    @MethodCondition(method = "doesSupportLegacyVersions")
    public void versionLowerThanSupportedByServer(WorkflowRunner runner) {
        runner.replaceSupportedCiphersuites = true;

        Config c = this.getConfig();
        ProtocolVersion version = ProtocolVersion.SSL3;
        List<ProtocolVersion> versions = context.getConfig().getSiteReport().getVersions();
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
        cha.setRecords(record);

        WorkflowTrace trace = new WorkflowTrace();
        trace.addTlsActions(
                cha,
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(trace, c).validateFinal(i -> {
            Validator.receivedFatalAlert(i);

            AlertMessage alert = i.getWorkflowTrace().getFirstReceivedMessage(AlertMessage.class);
            if (alert == null) return;
            Validator.testAlertDescription(i, AlertDescription.PROTOCOL_VERSION, alert);
        });

    }

    @TlsTest(description = "Thus, TLS server compliant with this specification MUST accept any value {03,XX} as the " +
            "record layer version number for ClientHello.", interoperabilitySeverity = SeverityLevel.CRITICAL)
    public void acceptAnyRecordVersionNumber(WorkflowRunner runner) {
        Config c = this.getConfig();
        runner.replaceSupportedCiphersuites = true;

        Record record = new Record();
        record.setProtocolVersion(Modifiable.explicit(new byte[]{0x03, 0x05}));
        SendAction sendAction = new SendAction(new ClientHelloMessage(c));
        sendAction.setRecords(record);

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                sendAction,
                new ReceiveTillAction(new ServerHelloDoneMessage())
        );

        runner.execute(workflowTrace, c).validateFinal(Validator::executedAsPlanned);
    }


}
