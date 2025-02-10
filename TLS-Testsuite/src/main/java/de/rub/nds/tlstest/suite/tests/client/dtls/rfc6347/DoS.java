package de.rub.nds.tlstest.suite.tests.client.dtls.rfc6347;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.ClientTest;
import de.rub.nds.anvilcore.teststate.AnvilTestCase;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceResultUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Dtls12Test;
import java.util.Arrays;

@ClientTest
public class DoS extends Dtls12Test {

    @AnvilTest(id = "6347-tT9LA2Ba7T")
    /**
     * The test is successful if the first and second {@link ClientHelloMessage} contain exactly the
     * same values, except for the cookie and the cookie length.
     */
    public void responseToHelloVerifyRequest(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);
        c.setDtlsCookieExchange(true);

        WorkflowTrace trace =
                runner.generateWorkflowTraceUntilLastSendingMessage(
                        WorkflowTraceType.HELLO, HandshakeMessageType.SERVER_HELLO);

        State state = runner.execute(trace, c);

        Validator.executedAsPlanned(state, testCase);

        ClientHelloMessage firstClientHello =
                (ClientHelloMessage)
                        WorkflowTraceResultUtil.getFirstReceivedMessage(
                                trace, HandshakeMessageType.CLIENT_HELLO);
        HelloVerifyRequestMessage helloVerifyRequest =
                (HelloVerifyRequestMessage)
                        WorkflowTraceResultUtil.getFirstSentMessage(
                                trace, HandshakeMessageType.HELLO_VERIFY_REQUEST);
        ClientHelloMessage secondClientHello =
                (ClientHelloMessage)
                        WorkflowTraceResultUtil.getLastReceivedMessage(
                                trace, HandshakeMessageType.CLIENT_HELLO);
        assertTrue(firstClientHello != null, "Did not receive first Client Hello messages");
        assertTrue(secondClientHello != null, "Did not receive second Client Hello messages");

        assertTrue(
                firstClientHello.getCookieLength().getValue() == 0,
                "Did not receive first Client Hello messages without cookie");

        testIfClientHelloFieldsAreEqualWithoutCookie(firstClientHello, secondClientHello);

        assertTrue(
                helloVerifyRequest.getCookie().equals(secondClientHello.getCookie()),
                "Did not recive the cookie from the hello verify request message in the second client hello message.");
    }

    /**
     * This method checks if the values of the two passed \{@link ClientHelloMessage} are identical.
     * The value of the cookie is not considered. If both messages are different, an \{@link
     * AssertionError} is thrown.
     *
     * @param firstClientHello the first \{@link ClientHelloMessage} send from the client
     * @param retryClientHello the second \{@link ClientHelloMessage} send from the client
     */
    private void testIfClientHelloFieldsAreEqualWithoutCookie(
            ClientHelloMessage firstClientHello, ClientHelloMessage retryClientHello) {
        assertTrue(
                Arrays.equals(
                        firstClientHello.getCipherSuites().getValue(),
                        retryClientHello.getCipherSuites().getValue()),
                "Offered CipherSuites are not identical");
        assertArrayEquals(
                firstClientHello.getCompressions().getValue(),
                retryClientHello.getCompressions().getValue(),
                "Offered CompressionLists are not identical");
        assertTrue(
                Arrays.equals(
                        firstClientHello.getRandom().getValue(),
                        retryClientHello.getRandom().getValue()),
                "Selected ClientRandoms are not identical");
        assertTrue(
                Arrays.equals(
                        firstClientHello.getProtocolVersion().getValue(),
                        retryClientHello.getProtocolVersion().getValue()),
                "Selected ProtocolVersions are not identical");
        assertTrue(
                Arrays.equals(
                        firstClientHello.getSessionId().getValue(),
                        retryClientHello.getSessionId().getValue()),
                "Offered SessionIDs are not identical");
    }
}
