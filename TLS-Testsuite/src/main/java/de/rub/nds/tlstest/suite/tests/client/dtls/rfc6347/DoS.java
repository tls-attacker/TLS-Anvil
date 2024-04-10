package de.rub.nds.tlstest.suite.tests.client.dtls.rfc6347;

import static org.junit.Assert.assertTrue;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.ClientTest;
import de.rub.nds.anvilcore.teststate.AnvilTestCase;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Dtls12Test;
import java.util.Arrays;
import org.junit.Assert;

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
                        WorkflowTraceUtil.getFirstReceivedMessage(
                                HandshakeMessageType.CLIENT_HELLO, trace);
        HelloVerifyRequestMessage helloVerifyRequest =
                (HelloVerifyRequestMessage)
                        WorkflowTraceUtil.getFirstSendMessage(
                                HandshakeMessageType.HELLO_VERIFY_REQUEST, trace);
        ClientHelloMessage secondClientHello =
                (ClientHelloMessage)
                        WorkflowTraceUtil.getLastReceivedMessage(
                                HandshakeMessageType.CLIENT_HELLO, trace);
        assertTrue("Did not receive first Client Hello messages", firstClientHello != null);
        assertTrue("Did not receive second Client Hello messages", secondClientHello != null);

        assertTrue(
                "Did not receive first Client Hello messages without cookie",
                firstClientHello.getCookieLength().getValue() == 0);

        testIfClientHelloFieldsAreEqualWithoutCookie(firstClientHello, secondClientHello);

        assertTrue(
                "Did not recive the cookie from the hello verify request message in the second client hello message.",
                helloVerifyRequest.getCookie().equals(secondClientHello.getCookie()));
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
                "Offered CipherSuites are not identical",
                Arrays.equals(
                        firstClientHello.getCipherSuites().getValue(),
                        retryClientHello.getCipherSuites().getValue()));
        Assert.assertArrayEquals(
                "Offered CompressionLists are not identical",
                firstClientHello.getCompressions().getValue(),
                retryClientHello.getCompressions().getValue());
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
                "Offered SessionIDs are not identical",
                Arrays.equals(
                        firstClientHello.getSessionId().getValue(),
                        retryClientHello.getSessionId().getValue()));
    }
}
