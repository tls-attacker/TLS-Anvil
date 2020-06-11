package de.rub.nds.tlstest.suite.tests.server.tls12.rfc5246;

import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.ServerTest;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.constants.AssertMsgs;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;

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
            assertTrue(AssertMsgs.WorkflowNotExecuted, trace.executedAsPlanned());

            ServerHelloMessage msg = trace.getFirstReceivedMessage(ServerHelloMessage.class);
            assertArrayEquals("Invalid ProtocolVersion negotiated",
                    ProtocolVersion.getHighestProtocolVersion(context.getConfig().getSiteReport().getVersions()).getValue(),
                    msg.getProtocolVersion().getValue()
            );
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

        runner.execute(workflowTrace, c).validateFinal(i -> {
            WorkflowTrace trace = i.getWorkflowTrace();
            assertTrue(AssertMsgs.WorkflowNotExecuted, trace.executedAsPlanned());
        });
    }


}
