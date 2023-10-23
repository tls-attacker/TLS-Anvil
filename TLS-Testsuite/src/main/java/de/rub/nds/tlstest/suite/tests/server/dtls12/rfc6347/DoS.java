package de.rub.nds.tlstest.suite.tests.server.dtls12.rfc6347;

import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceivingAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.ScopeExtensions;
import de.rub.nds.tlstest.framework.annotations.ServerTest;
import de.rub.nds.tlstest.framework.annotations.TestDescription;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.annotations.categories.ComplianceCategory;
import de.rub.nds.tlstest.framework.annotations.categories.HandshakeCategory;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.DerivationType;
import de.rub.nds.tlstest.framework.testClasses.Dtls12Test;
import java.math.BigInteger;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@RFC(number = 6347, section = "4.2.1. Denial-of-Service Countermeasures")
@Tag("dtls12")
public class DoS extends Dtls12Test {

    @Tag("Test7")
    @TlsTest(
            description =
                    "The server MUST use the same"
                            + "   version number in the HelloVerifyRequest that it would use when"
                            + "   sending a ServerHello.")
    /**
     * This test test, wether the same {@link ProtocolVersion} is used in the {@link
     * HelloVerifyRequestMessage} and the {@link ServerHelloMessage}.
     */
    public void sameVersionNumberServerHello(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {

        Config c = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace trace =
                runner.generateWorkflowTraceUntilSendingMessage(
                        WorkflowTraceType.HELLO, HandshakeMessageType.FINISHED);

        runner.execute(trace, c)
                .validateFinal(
                        i -> {
                            assertTrue(trace.executedAsPlanned(), trace.getTlsActions().toString());

                            HelloVerifyRequestMessage helloVerifyRequest =
                                    (HelloVerifyRequestMessage)
                                            WorkflowTraceUtil.getLastReceivedMessage(
                                                    HandshakeMessageType.HELLO_VERIFY_REQUEST,
                                                    trace);
                            ServerHelloMessage serverHello =
                                    (ServerHelloMessage)
                                            WorkflowTraceUtil.getLastReceivedMessage(
                                                    HandshakeMessageType.SERVER_HELLO, trace);
                            assertTrue(
                                    helloVerifyRequest != null,
                                    "Did not receive Hello Verify Request messages");
                            assertTrue(
                                    serverHello != null, "Did not receive Server Hello messages");

                            assertTrue(
                                    helloVerifyRequest
                                            .getProtocolVersion()
                                            .equals(serverHello.getProtocolVersion()),
                                    "Did not recive the version number from the hello verify request message in the server hello message.");
                        });
    }

    @Tag("Test8")
    @TlsTest(
            description =
                    "In order to avoid sequence number duplication in case of multiple HelloVerifyRequests, the server MUST use the record sequence number in the ClientHello as the record sequence number in the HelloVerifyRequest.")
    /**
     * This test test, wether the same sequenceNumber is used in the {@link ClientHelloMessage} and
     * the {@link HelloVerifyRequestMessage}.
     */
    public void clientSequenceNumberInHelloVerifyRequest(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        WorkflowTrace trace =
                runner.generateWorkflowTraceUntilReceivingMessage(
                        WorkflowTraceType.HELLO, HandshakeMessageType.HELLO_VERIFY_REQUEST);

        trace.addTlsActions(new ReceiveAction(new HelloVerifyRequestMessage()));

        runner.execute(trace, c)
                .validateFinal(
                        i -> {
                            WorkflowTrace executedTrace = i.getWorkflowTrace();
                            Validator.executedAsPlanned(i);

                            BigInteger clientHelloSeqNum =
                                    executedTrace
                                            .getFirstSendingAction()
                                            .getSendRecords()
                                            .get(0)
                                            .getSequenceNumber()
                                            .getValue();
                            BigInteger helloVerifyRequestSeqNum = null;

                            for (ReceivingAction tlsAction : executedTrace.getReceivingActions()) {
                                int helloVerifyRequestNum = 0;
                                if (helloVerifyRequestSeqNum == null) {
                                    for (ProtocolMessage message :
                                            tlsAction.getReceivedMessages()) {
                                        if (message.getClass() == HelloVerifyRequestMessage.class) {
                                            helloVerifyRequestSeqNum =
                                                    tlsAction
                                                            .getReceivedRecords()
                                                            .get(helloVerifyRequestNum)
                                                            .getSequenceNumber()
                                                            .getValue();
                                            break;
                                        }
                                        helloVerifyRequestNum++;
                                    }
                                }
                            }

                            assertTrue(
                                    clientHelloSeqNum != null,
                                    "Did not send Client Hello messages");
                            assertTrue(
                                    helloVerifyRequestSeqNum != null,
                                    "Did not receive Hello Verify Request messages");
                            assertTrue(
                                    clientHelloSeqNum.compareTo(helloVerifyRequestSeqNum) == 0,
                                    "Did not recive the message sequence from the client hello in the hello verify request message.");
                            assertTrue(
                                    helloVerifyRequestSeqNum.intValue() == 0,
                                    "The Sequence Number of the HelloVerifyRequest is not 0.");
                        });
    }

    @Tag("Test9")
    @TlsTest(
            description =
                    "In order to avoid sequence number duplication in"
                            + "   case of multiple cookie exchanges, the server MUST use the record"
                            + "   sequence number in the ClientHello as the record sequence number in"
                            + "   its initial ServerHello.")
    /**
     * This test test, wether the same sequenceNumber is used in the {@link ClientHelloMessage} and
     * the {@link ServerHelloMessage}.
     */
    public void sequenceNumberFromClientHelloInServerHello(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        WorkflowTrace trace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);

        runner.execute(trace, c)
                .validateFinal(
                        i -> {
                            WorkflowTrace executedTrace = i.getWorkflowTrace();

                            Validator.executedAsPlanned(i);

                            BigInteger clientHelloSeqNum = null;
                            if (executedTrace.getSendingActions().size() > 1) {
                                clientHelloSeqNum =
                                        executedTrace
                                                .getSendingActions()
                                                .get(1)
                                                .getSendRecords()
                                                .get(0)
                                                .getSequenceNumber()
                                                .getValue();
                            }
                            BigInteger serverHelloRequestSeqNum = null;

                            for (ReceivingAction tlsAction : executedTrace.getReceivingActions()) {
                                int helloVerifyRequestNum = 0;
                                if (serverHelloRequestSeqNum == null) {
                                    for (ProtocolMessage message :
                                            tlsAction.getReceivedMessages()) {
                                        if (message.getClass() == ServerHelloMessage.class) {
                                            serverHelloRequestSeqNum =
                                                    tlsAction
                                                            .getReceivedRecords()
                                                            .get(helloVerifyRequestNum)
                                                            .getSequenceNumber()
                                                            .getValue();
                                            break;
                                        }
                                        helloVerifyRequestNum++;
                                    }
                                }
                            }

                            assertTrue(
                                    clientHelloSeqNum != null,
                                    "Did not send Client Hello messages");
                            assertTrue(
                                    serverHelloRequestSeqNum != null,
                                    "Did not receive Server Hello messages");
                            assertTrue(
                                    clientHelloSeqNum.compareTo(serverHelloRequestSeqNum) == 0,
                                    "Did not recive the message sequence from the client hello in the server hello message.");
                        });
    }

    @Tag("Test10")
    @TlsTest(
            description =
                    "The server then verifies the cookie and proceeds with the handshake only if it is valid.")
    @ServerTest
    @ScopeExtensions({DerivationType.DTLS_COOKIE_BITMASK})
    /**
     * The test checks the handling of the server when it receives a wrong cookie in the {@link
     * ClientHelloMessage}. In this case, the server must deal with the ClientHello in the same way
     * as a ClientHello without a cookie and resend a {@link HelloVerifyRequestMessage}.
     */
    public void invalidClientHelloCookie(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        byte[] bitmask = derivationContainer.buildBitmask();

        WorkflowTrace trace =
                runner.generateWorkflowTraceUntilReceivingMessage(
                        WorkflowTraceType.HELLO, HandshakeMessageType.HELLO_VERIFY_REQUEST);

        ClientHelloMessage clientHelloMessage = new ClientHelloMessage(c);
        clientHelloMessage.setCookie(Modifiable.xor(bitmask, 0));

        trace.addTlsAction(new SendAction(clientHelloMessage));
        trace.addTlsAction(new ReceiveAction(new HelloVerifyRequestMessage()));

        runner.execute(trace, c)
                .validateFinal(
                        i -> {
                            i.addAdditionalTestInfo(
                                    i.getWorkflowTrace().getMessageActions().toString());
                            Validator.executedAsPlanned(i);
                        });
    }

    @Tag("Test11")
    // @Test
    @TestDescription(
            "DTLS servers SHOULD perform a cookie exchange whenever a new"
                    + "   handshake is being performed.")
    @ComplianceCategory(SeverityLevel.LOW)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    // @ServerTest
    public void recordFragmentationSupported() {
        assertTrue(
                context.getSiteReport().getResult(TlsAnalyzedProperty.SUPPORTS_DTLS_COOKIE_EXCHANGE)
                        == TestResults.TRUE,
                "DTLS cookie exchange has not been detected");
    }
}