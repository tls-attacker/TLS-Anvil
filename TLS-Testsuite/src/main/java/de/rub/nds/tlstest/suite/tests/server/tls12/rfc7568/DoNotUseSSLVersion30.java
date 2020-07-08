package de.rub.nds.tlstest.suite.tests.server.tls12.rfc7568;

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
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.ServerTest;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.constants.AssertMsgs;
import de.rub.nds.tlstest.framework.execution.AnnotatedState;
import de.rub.nds.tlstest.framework.execution.AnnotatedStateContainer;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;

import static org.junit.Assert.*;

@RFC(number = 7568, section = "3")
@ServerTest
public class DoNotUseSSLVersion30 extends Tls12Test {

    @TlsTest(description = "SSLv3 MUST NOT be used. Negotiation of SSLv3 from any version of TLS " +
            "MUST NOT be permitted.\n" +
            "Pragmatically, clients MUST NOT send a ClientHello with " +
            "ClientHello.client_version set to {03,00}. Similarly, servers MUST " +
            "NOT send a ServerHello with ServerHello.server_version set to " +
            "{03,00}. Any party receiving a Hello message with the protocol " +
            "version set to {03,00} MUST respond with a \"protocol_version\" alert " +
            "message and close the connection.")
    public void sendClientHelloVersion0300(WorkflowRunner runner) {
        Config config = this.getConfig();
        runner.replaceSupportedCiphersuites = true;

        ClientHelloMessage clientHelloMessage = new ClientHelloMessage(config);
        clientHelloMessage.setProtocolVersion(Modifiable.explicit(new byte[]{0x03, 0x00}));

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                new SendAction(clientHelloMessage),
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(workflowTrace, config).validateFinal(i -> {
            WorkflowTrace trace = i.getWorkflowTrace();
            Validator.receivedFatalAlert(i);

            AlertMessage msg = trace.getFirstReceivedMessage(AlertMessage.class);
            byte description = msg.getDescription().getValue();
            try {
                assertEquals(AssertMsgs.NoFatalAlert, AlertDescription.PROTOCOL_VERSION.getValue(), description);
            } catch (AssertionError err) {
                i.addAdditionalResultInfo(String.format("Received invalid alert description. Execpted: %s, got: %s", AlertDescription.PROTOCOL_VERSION, AlertDescription.getAlertDescription(description)));
            }

        });

    }

    @TlsTest(description = "TLS servers MUST accept any value " +
            "{03,XX} (including {03,00}) as the record layer version number for " +
            "ClientHello, but they MUST NOT negotiate SSLv3.")
    public void sendClientHelloVersion0300WithDifferentVersionInTheRecord(WorkflowRunner runner) {
        Config config = this.getConfig();
        runner.replaceSupportedCiphersuites = true;

        AnnotatedStateContainer container = new AnnotatedStateContainer();

        for (byte i : new byte[]{0x00, 0x01, 0x02, 0x04, 0x05, (byte)0xff}) {
            Record record = new Record();
            record.setProtocolVersion(Modifiable.explicit(new byte[]{0x03, i}));
            ClientHelloMessage clientHelloMessage = new ClientHelloMessage();

            SendAction sendAction = new SendAction(clientHelloMessage);
            sendAction.setRecords(record);

            WorkflowTrace workflowTrace = new WorkflowTrace();
            workflowTrace.addTlsActions(
                    sendAction,
                    new ReceiveTillAction(new ServerHelloDoneMessage())
            );

            AnnotatedState state = new AnnotatedState(new State(config, workflowTrace));
            state.addAdditionalTestInfo(String.format("RecordLayerVersion 0x03 0x%02x", i));

            runner.setStateModifier(s -> {
                s.addAdditionalTestInfo(String.format("Set protocol version to 0x03 0x%2x", i));
                return null;
            });
            container.addAll(runner.prepare(state));
        }

        runner.execute(container).validateFinal(i -> {
            WorkflowTrace trace = i.getWorkflowTrace();
            assertTrue(AssertMsgs.WorkflowNotExecuted, trace.executedAsPlanned());

            ServerHelloMessage shm = trace.getFirstReceivedMessage(ServerHelloMessage.class);
            assertNotNull(AssertMsgs.ServerHelloNotReceived, shm);

            assertArrayEquals("Invalid TLS version negotiated", new byte[]{0x03, 0x03}, shm.getProtocolVersion().getValue());
        });
    }

}
