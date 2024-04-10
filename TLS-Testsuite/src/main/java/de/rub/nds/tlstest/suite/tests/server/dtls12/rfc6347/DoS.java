package de.rub.nds.tlstest.suite.tests.server.dtls12.rfc6347;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.IncludeParameter;
import de.rub.nds.anvilcore.annotation.MethodCondition;
import de.rub.nds.anvilcore.annotation.ServerTest;
import de.rub.nds.anvilcore.teststate.AnvilTestCase;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceivingAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendingAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Dtls12Test;
import de.rub.nds.tlstest.suite.util.DtlsTestConditions;
import java.math.BigInteger;
import org.junit.jupiter.api.Tag;

@ServerTest
public class DoS extends Dtls12Test {

    private static final long MODIFIED_SEQUENCE_NUMBER = 999;

    @AnvilTest(id = "6347-z0AiXbV3Y6")
    public void sameVersionNumberServerHello(AnvilTestCase testCase, WorkflowRunner runner) {

        Config c = getPreparedConfig(runner);
        WorkflowTrace trace =
                runner.generateWorkflowTraceUntilSendingMessage(
                        WorkflowTraceType.HELLO, HandshakeMessageType.FINISHED);

        State state = runner.execute(trace, c);

        assertTrue(trace.executedAsPlanned(), trace.getTlsActions().toString());

        HelloVerifyRequestMessage helloVerifyRequest =
                (HelloVerifyRequestMessage)
                        WorkflowTraceUtil.getLastReceivedMessage(
                                HandshakeMessageType.HELLO_VERIFY_REQUEST, trace);
        ServerHelloMessage serverHello =
                (ServerHelloMessage)
                        WorkflowTraceUtil.getLastReceivedMessage(
                                HandshakeMessageType.SERVER_HELLO, trace);
        assertTrue(helloVerifyRequest != null, "Did not receive Hello Verify Request messages");
        assertTrue(serverHello != null, "Did not receive Server Hello messages");

        assertTrue(
                helloVerifyRequest.getProtocolVersion().equals(serverHello.getProtocolVersion()),
                "Did not recive the version number from the hello verify request message in the server hello message.");

        testCase.addAdditionalResultInfo(
                "This mandatory RFC requirement contradicts the statement from Sect. 4.2.1 in RFC 6347 that implementations SHOULD use DTLS 1.0 in the HelloVerifyRequest regardless of the version negotiated in the ServerHello");
    }

    @AnvilTest(id = "6347-5R0A5tlkOm")
    public void clientSequenceNumberInHelloVerifyRequest(
            AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);

        WorkflowTrace trace =
                runner.generateWorkflowTraceUntilReceivingMessage(
                        WorkflowTraceType.HELLO, HandshakeMessageType.HELLO_VERIFY_REQUEST);
        Record preparedRecord = new Record();
        preparedRecord.setSequenceNumber(
                Modifiable.explicit(BigInteger.valueOf(MODIFIED_SEQUENCE_NUMBER)));
        trace.getFirstSendingAction().getSendRecords().add(preparedRecord);
        trace.addTlsActions(new ReceiveAction(new HelloVerifyRequestMessage()));

        State state = runner.execute(trace, c);

        WorkflowTrace executedTrace = state.getWorkflowTrace();
        Validator.executedAsPlanned(state, testCase);

        HelloVerifyRequestMessage hvrMsg =
                executedTrace.getLastReceivedMessage(HelloVerifyRequestMessage.class);
        ReceivingAction receivingAction =
                (ReceivingAction)
                        WorkflowTraceUtil.getLastReceivingActionForMessage(
                                HandshakeMessageType.HELLO_VERIFY_REQUEST, executedTrace);
        assertNotNull(hvrMsg, "Did not receive a HelloVerifyRequest");
        // potential retransmission also use the explicitly modified sequence
        // number, hence, the HVR should also have this sequence number
        long hvrSequenceNumber =
                receivingAction
                        .getReceivedRecords()
                        .get(0)
                        .getSequenceNumber()
                        .getValue()
                        .longValue();
        assertEquals(
                MODIFIED_SEQUENCE_NUMBER,
                hvrSequenceNumber,
                "Server did not use sequence number from Client Hello record");
    }

    @AnvilTest(id = "6347-56hL9Blfzp")
    public void sequenceNumberFromClientHelloInServerHello(
            AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);

        WorkflowTrace trace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        Record preparedRecord = new Record();
        preparedRecord.setSequenceNumber(
                Modifiable.explicit(BigInteger.valueOf(MODIFIED_SEQUENCE_NUMBER)));
        trace.getLastSendingAction().getSendRecords().add(preparedRecord);

        State state = runner.execute(trace, c);

        WorkflowTrace executedTrace = state.getWorkflowTrace();
        Validator.executedAsPlanned(state, testCase);

        ServerHelloMessage serverHello =
                executedTrace.getLastReceivedMessage(ServerHelloMessage.class);
        ReceivingAction receivingAction =
                (ReceivingAction)
                        WorkflowTraceUtil.getLastReceivingActionForMessage(
                                HandshakeMessageType.SERVER_HELLO, executedTrace);
        assertNotNull(serverHello, "Did not receive a HelloVerifyRequest");
        // potential retransmission also use the explicitly modified sequence
        // number, hence, the HVR should also have this sequence number
        long serverHelloSqn =
                receivingAction
                        .getReceivedRecords()
                        .get(0)
                        .getSequenceNumber()
                        .getValue()
                        .longValue();
        assertEquals(
                MODIFIED_SEQUENCE_NUMBER,
                serverHelloSqn,
                "Server did not use sequence number from Client Hello record");
    }

    @Tag("Test10")
    @AnvilTest(id = "6347-g65TNbT3uV")
    @IncludeParameter("DTLS_COOKIE_BITMASK")
    @MethodCondition(clazz = DtlsTestConditions.class, method = "serverSendsHelloVerifyRequest")
    public void invalidClientHelloCookie(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);
        byte[] bitmask = parameterCombination.buildBitmask();

        WorkflowTrace trace =
                runner.generateWorkflowTraceUntilReceivingMessage(
                        WorkflowTraceType.HELLO, HandshakeMessageType.HELLO_VERIFY_REQUEST);

        ClientHelloMessage clientHelloMessage = new ClientHelloMessage(c);
        clientHelloMessage.setCookie(Modifiable.xor(bitmask, 0));

        trace.addTlsAction(new SendAction(clientHelloMessage));
        trace.addTlsAction(new ReceiveAction(new HelloVerifyRequestMessage()));

        State state = runner.execute(trace, c);

        testCase.addAdditionalTestInfo(state.getWorkflowTrace().getMessageActions().toString());
        Validator.executedAsPlanned(state, testCase);
    }

    @AnvilTest(id = "6347-76Jna7IPv8")
    public void negotiateDtls12viaRecordHeader(AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);
        WorkflowTrace trace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        trace.getFirstSendMessage(ClientHelloMessage.class)
                .setProtocolVersion(Modifiable.explicit(ProtocolVersion.DTLS10.getValue()));
        trace.getLastSendMessage(ClientHelloMessage.class)
                .setProtocolVersion(Modifiable.explicit(ProtocolVersion.DTLS10.getValue()));
        Record preparedRecord1 = new Record();
        Record preparedRecord2 = new Record();
        preparedRecord1.setProtocolVersion(Modifiable.explicit(ProtocolVersion.DTLS12.getValue()));
        ((SendingAction)
                        WorkflowTraceUtil.getFirstSendingActionForMessage(
                                HandshakeMessageType.CLIENT_HELLO, trace))
                .getSendRecords()
                .add(preparedRecord1);
        // when server does not require a HVR cycle, this will only overwrite the previous record
        preparedRecord2.setProtocolVersion(Modifiable.explicit(ProtocolVersion.DTLS12.getValue()));
        ((SendingAction)
                        WorkflowTraceUtil.getLastSendingActionForMessage(
                                HandshakeMessageType.CLIENT_HELLO, trace))
                .getSendRecords()
                .add(preparedRecord2);

        State state = runner.execute(trace, config);
        // peer must reject handshake or negotiate DTLS 1.0
        if (state.getWorkflowTrace().executedAsPlanned()) {
            assertFalse(
                    state.getTlsContext().getSelectedProtocolVersion() == ProtocolVersion.DTLS12,
                    "Server negotiated DTLS 1.2 based on record header");
        }
    }
}
