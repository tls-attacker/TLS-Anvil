package de.rub.nds.tlstest.suite.tests.client.dtls.rfc6347;

import static org.junit.Assert.assertTrue;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.ClientTest;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Dtls12Test;
import java.util.Arrays;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@RFC(number = 6347, section = "4.2.1. Denial-of-Service Countermeasures")
@Tag("dtls12")
public class DoS extends Dtls12Test {

    @Tag("Test12")
    @TlsTest(description = "The client MUST retransmit the ClientHello with the cookie added.")
    @ClientTest
    /**
     * This test validates that a client responds to a {@link HelloVerifyRequestMessage} with a
     * second {@link ClientHelloMessage} that contains the cookie from the {@link
     * HelloVerifyRequestMessage}.
     */
    public void clintHelloWithoutAndWithCookie(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        c.setDtlsCookieExchange(true);

        WorkflowTrace trace = runner.generateWorkflowTrace(WorkflowTraceType.SHORT_HELLO);

        runner.execute(trace, c)
                .validateFinal(
                        i -> {
                            WorkflowTrace executedTrace = i.getWorkflowTrace();
                            Validator.executedAsPlanned(i);

                            HelloVerifyRequestMessage helloVerifyRequest =
                                    (HelloVerifyRequestMessage)
                                            WorkflowTraceUtil.getFirstSendMessage(
                                                    HandshakeMessageType.HELLO_VERIFY_REQUEST,
                                                    executedTrace);
                            ClientHelloMessage secondClientHello =
                                    (ClientHelloMessage)
                                            WorkflowTraceUtil.getLastReceivedMessage(
                                                    HandshakeMessageType.CLIENT_HELLO,
                                                    executedTrace);
                            assertTrue(
                                    "Did not send Hello Verify Request messages",
                                    helloVerifyRequest != null);
                            assertTrue(
                                    "Did not receive second Client Hello messages",
                                    secondClientHello != null);
                            assertTrue(
                                    "Did not receive second Client Hello messages with cookie",
                                    secondClientHello.getCookieLength().getValue() != 0);

                            assertTrue(
                                    "Did not recive the cookie from the hello verify request message in the second client hello message.",
                                    helloVerifyRequest
                                            .getCookie()
                                            .equals(secondClientHello.getCookie()));
                        });
    }

    @Tag("Test13")
    @TlsTest(
            description =
                    "When responding to a HelloVerifyRequest, the client MUST use the same"
                            + "   parameter values (version, random, session_id, cipher_suites,"
                            + "   compression_method) as it did in the original ClientHello.")
    @ClientTest
    /**
     * The test is successful if the first and second {@link ClientHelloMessage} contain exactly the
     * same values, except for the cookie and the cookie length.
     */
    public void responseToHelloVerifyRequest(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        c.setDtlsCookieExchange(true);

        WorkflowTrace trace =
                runner.generateWorkflowTraceUntilLastSendingMessage(
                        WorkflowTraceType.HELLO, HandshakeMessageType.SERVER_HELLO);

        runner.execute(trace, c)
                .validateFinal(
                        i -> {
                            Validator.executedAsPlanned(i);

                            ClientHelloMessage firstClientHello =
                                    (ClientHelloMessage)
                                            WorkflowTraceUtil.getFirstReceivedMessage(
                                                    HandshakeMessageType.CLIENT_HELLO, trace);
                            ClientHelloMessage secondClientHello =
                                    (ClientHelloMessage)
                                            WorkflowTraceUtil.getLastReceivedMessage(
                                                    HandshakeMessageType.CLIENT_HELLO, trace);
                            assertTrue(
                                    "Did not receive first Client Hello messages",
                                    firstClientHello != null);
                            assertTrue(
                                    "Did not receive second Client Hello messages",
                                    secondClientHello != null);

                            assertTrue(
                                    "Did not receive first Client Hello messages without cookie",
                                    firstClientHello.getCookieLength().getValue() == 0);
                            assertTrue(
                                    "Did not receive second Client Hello messages with cookie",
                                    secondClientHello.getCookieLength().getValue() >= 0);

                            testIfClientHelloFieldsAreEqualWithoutCookie(
                                    firstClientHello, secondClientHello);
                        });
    }

    /**
     * This method checks if the values of the two passed \{@link ClientHelloMessage} are identical.
     * The value of the cookie is not considered. If both messages are different, an \{@link
     * AssertionException} is thrown.
     *
     * @param firstClientHello the first \{@link ClientHelloMessage} send from the client
     * @param retryClientHello the second \{@link ClientHelloMessage} send from the client
     */
    private void testIfClientHelloFieldsAreEqualWithoutCookie(
            ClientHelloMessage firstClientHello, ClientHelloMessage retryClientHello) {
        assertTrue(
                "Offered CipherSuites are not identical",
                Arrays.equals(
                        firstClientHello.getCipherSuites().getValue(),
                        retryClientHello.getCipherSuites().getValue()));
        assertTrue(
                "Offered CompressionList lengths are not identical",
                firstClientHello
                        .getCompressionLength()
                        .getValue()
                        .equals(retryClientHello.getCompressionLength().getValue()));
        assertTrue(
                "Selected ClientRandoms are not identical",
                Arrays.equals(
                        firstClientHello.getRandom().getValue(),
                        retryClientHello.getRandom().getValue()));
        assertTrue(
                "Selected ProtocolVersions are not identical",
                Arrays.equals(
                        firstClientHello.getProtocolVersion().getValue(),
                        retryClientHello.getProtocolVersion().getValue()));
        assertTrue(
                "TLS 1.3 compatibility SessionIDs are not identical",
                Arrays.equals(
                        firstClientHello.getSessionId().getValue(),
                        retryClientHello.getSessionId().getValue()));
    }
}