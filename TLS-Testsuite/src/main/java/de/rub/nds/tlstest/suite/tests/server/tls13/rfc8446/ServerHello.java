/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.server.tls13.rfc8446;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.DynamicValueConstraints;
import de.rub.nds.anvilcore.annotation.MethodCondition;
import de.rub.nds.anvilcore.annotation.ServerTest;
import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.teststate.AnvilTestCase;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceResultUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.constants.AssertMsgs;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.derivationParameter.ProtocolVersionDerivation;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
import de.rub.nds.tlstest.suite.tests.both.tls13.rfc8446.SharedExtensionTests;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;

@ServerTest
public class ServerHello extends Tls13Test {

    public ConditionEvaluationResult supportsTls12() {
        if (context.getFeatureExtractionResult()
                .getSupportedVersions()
                .contains(ProtocolVersion.TLS12)) return ConditionEvaluationResult.enabled("");
        return ConditionEvaluationResult.disabled("No TLS 1.2 support");
    }

    public ConditionEvaluationResult supportsTls11() {
        if (context.getFeatureExtractionResult()
                .getSupportedVersions()
                .contains(ProtocolVersion.TLS11)) return ConditionEvaluationResult.enabled("");
        return ConditionEvaluationResult.disabled("No TLS 1.1 support");
    }

    public ConditionEvaluationResult supportsTls10() {
        if (context.getFeatureExtractionResult()
                .getSupportedVersions()
                .contains(ProtocolVersion.TLS10)) return ConditionEvaluationResult.enabled("");
        return ConditionEvaluationResult.disabled("No TLS 1.0 support");
    }

    @AnvilTest(id = "8446-8bcX8V9Zve")
    public void testLegacyVersion(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                new SendAction(new ClientHelloMessage(c)),
                new ReceiveTillAction(new CertificateVerifyMessage()));

        State state = runner.execute(workflowTrace, c);

        WorkflowTrace trace = state.getWorkflowTrace();
        Validator.executedAsPlanned(state, testCase);

        ServerHelloMessage msg = trace.getFirstReceivedMessage(ServerHelloMessage.class);
        assertNotNull(msg, AssertMsgs.SERVER_HELLO_NOT_RECEIVED);
        assertArrayEquals(
                new byte[] {0x03, 0x03},
                msg.getProtocolVersion().getValue(),
                "Invalid legacy version");
    }

    @AnvilTest(id = "8446-p17y8QGnbD")
    @MethodCondition(method = "supportsTls12")
    @KeyExchange(supported = KeyExchangeType.ALL12)
    public void testServerRandomFor12(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = prepareConfig(context.getConfig().createConfig(), runner);

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                new SendAction(new ClientHelloMessage(c)),
                new ReceiveTillAction(new ServerHelloDoneMessage()));

        State state = runner.execute(workflowTrace, c);

        WorkflowTrace trace = state.getWorkflowTrace();
        Validator.executedAsPlanned(state, testCase);

        ServerHelloMessage msg = trace.getFirstReceivedMessage(ServerHelloMessage.class);
        assertNotNull(msg, AssertMsgs.SERVER_HELLO_NOT_RECEIVED);
        byte[] random = msg.getRandom().getValue();
        assertArrayEquals(
                new byte[] {0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01},
                Arrays.copyOfRange(random, random.length - 8, random.length),
                "Invalid random");
    }

    @AnvilTest(id = "8446-CyEBbGYnB5")
    @MethodCondition(method = "supportsTls11")
    @DynamicValueConstraints(affectedIdentifiers = "CIPHER_SUITE", methods = "isTls11CipherSuite")
    @KeyExchange(supported = KeyExchangeType.ALL12)
    @Tag("new")
    public void testServerRandomFor11(AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = prepareConfig(context.getConfig().createConfig(), runner);
        config.setHighestProtocolVersion(ProtocolVersion.TLS11);
        WorkflowTrace workflowTrace = new WorkflowTrace();
        ClientHelloMessage clientHello = new ClientHelloMessage(config);
        workflowTrace.addTlsActions(
                new SendAction(clientHello), new ReceiveTillAction(new ServerHelloDoneMessage()));

        State state = runner.execute(workflowTrace, config);

        WorkflowTrace trace = state.getWorkflowTrace();
        Validator.executedAsPlanned(state, testCase);

        ServerHelloMessage msg = trace.getFirstReceivedMessage(ServerHelloMessage.class);
        assertNotNull(msg, AssertMsgs.SERVER_HELLO_NOT_RECEIVED);
        byte[] random = msg.getRandom().getValue();
        assertArrayEquals(
                new byte[] {0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x00},
                Arrays.copyOfRange(random, random.length - 8, random.length),
                "Invalid random");
    }

    @AnvilTest(id = "8446-h8ESe4vrN3")
    @MethodCondition(method = "supportsTls10")
    @KeyExchange(supported = KeyExchangeType.ALL12)
    @DynamicValueConstraints(affectedIdentifiers = "CIPHER_SUITE", methods = "isTls10CipherSuite")
    @Tag("new")
    public void testServerRandomFor10(AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = prepareConfig(context.getConfig().createConfig(), runner);
        config.setHighestProtocolVersion(ProtocolVersion.TLS10);
        WorkflowTrace workflowTrace = new WorkflowTrace();
        ClientHelloMessage clientHello = new ClientHelloMessage(config);
        workflowTrace.addTlsActions(
                new SendAction(clientHello), new ReceiveTillAction(new ServerHelloDoneMessage()));

        State state = runner.execute(workflowTrace, config);

        WorkflowTrace trace = state.getWorkflowTrace();
        Validator.executedAsPlanned(state, testCase);

        ServerHelloMessage msg = trace.getFirstReceivedMessage(ServerHelloMessage.class);
        assertNotNull(msg, AssertMsgs.SERVER_HELLO_NOT_RECEIVED);
        byte[] random = msg.getRandom().getValue();
        assertArrayEquals(
                new byte[] {0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x00},
                Arrays.copyOfRange(random, random.length - 8, random.length),
                "Invalid random");
    }

    public boolean isTls10CipherSuite(CipherSuite cipherSuite) {
        return cipherSuite.isSupportedInProtocol(ProtocolVersion.TLS10);
    }

    public boolean isTls11CipherSuite(CipherSuite cipherSuite) {
        return cipherSuite.isSupportedInProtocol(ProtocolVersion.TLS11);
    }

    @AnvilTest(id = "8446-3FhkMFZvbt")
    public void testSessionIdEchoed(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);

        byte[] sessionId = new byte[32];
        sessionId[0] = (byte) 0xFF;
        sessionId[16] = (byte) 0xFF;

        c.setDefaultClientSessionId(sessionId);

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                new SendAction(new ClientHelloMessage(c)),
                new ReceiveTillAction(new CertificateVerifyMessage()));

        State state = runner.execute(workflowTrace, c);

        WorkflowTrace trace = state.getWorkflowTrace();
        Validator.executedAsPlanned(state, testCase);

        ServerHelloMessage msg = trace.getFirstReceivedMessage(ServerHelloMessage.class);
        assertNotNull(msg, AssertMsgs.SERVER_HELLO_NOT_RECEIVED);
        assertArrayEquals(sessionId, msg.getSessionId().getValue(), "Session ID not echoed");
    }

    @AnvilTest(id = "8446-aDiNwQZBTY")
    @Tag("new")
    public void testShortSessionIdEchoed(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);

        byte[] sessionId = new byte[8];
        sessionId[0] = (byte) 0xFF;

        c.setDefaultClientSessionId(sessionId);

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                new SendAction(new ClientHelloMessage(c)),
                new ReceiveTillAction(new CertificateVerifyMessage()));

        State state = runner.execute(workflowTrace, c);

        WorkflowTrace trace = state.getWorkflowTrace();
        Validator.executedAsPlanned(state, testCase);

        ServerHelloMessage msg = trace.getFirstReceivedMessage(ServerHelloMessage.class);
        assertNotNull(msg, AssertMsgs.SERVER_HELLO_NOT_RECEIVED);
        assertArrayEquals(sessionId, msg.getSessionId().getValue(), "Session ID not echoed");
    }

    @AnvilTest(id = "8446-S1VjZrpD1J")
    public void testCompressionValue(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        State state = runner.execute(workflowTrace, c);

        assertNotNull(
                state.getWorkflowTrace().getFirstReceivedMessage(ServerHelloMessage.class),
                "No ServerHello has been sent");
        assertEquals(
                0,
                state.getWorkflowTrace()
                        .getFirstReceivedMessage(ServerHelloMessage.class)
                        .getSelectedCompressionMethod()
                        .getValue()
                        .byteValue(),
                "invalid compression method");
    }

    @AnvilTest(id = "8446-sm3XxXFjbr")
    @Tag("new")
    public void testProvidedExtensions(AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        State state = runner.execute(workflowTrace, config);

        Validator.executedAsPlanned(state, testCase);
        ServerHelloMessage serverHello =
                state.getWorkflowTrace().getFirstReceivedMessage(ServerHelloMessage.class);
        ClientHelloMessage clientHello =
                (ClientHelloMessage)
                        WorkflowTraceResultUtil.getFirstSentMessage(
                                state.getWorkflowTrace(), HandshakeMessageType.CLIENT_HELLO);
        checkForForbiddenExtensions(serverHello);
        checkForUnproposedExtensions(serverHello, clientHello);
        SharedExtensionTests.checkForDuplicateExtensions(serverHello);
    }

    public static void checkForUnproposedExtensions(
            ServerHelloMessage serverHello, ClientHelloMessage clientHello) {
        assertNotNull(serverHello, "ServerHello was not received");
        assertNotNull(clientHello, "ClientHello was not provided");
        // MUST NOT contain any extensions that were not first
        // offered by the client in its ClientHello, with the
        // exception of optionally the "cookie"
        List<ExtensionType> illegalExtensions = new LinkedList<>();
        if (serverHello.getExtensions() != null) {
            for (ExtensionType extension :
                    serverHello.getExtensions().stream()
                            .map(ExtensionMessage::getExtensionTypeConstant)
                            .toArray(ExtensionType[]::new)) {
                if (!clientHello.containsExtension(extension)
                        && (extension != ExtensionType.COOKIE
                                || !serverHello.isTls13HelloRetryRequest())) {
                    illegalExtensions.add(extension);
                }
            }
            assertTrue(
                    illegalExtensions.isEmpty(),
                    "Server negotiated the following unproposed extensions: "
                            + illegalExtensions.parallelStream()
                                    .map(Enum::name)
                                    .collect(Collectors.joining(",")));
        }
    }

    public static void checkForForbiddenExtensions(ServerHelloMessage serverHello) {
        assertNotNull(serverHello, "ServerHello was not received");
        if (serverHello.getExtensions() != null) {
            // The server MUST NOT send a "psk_key_exchange_modes" extension.
            assertFalse(
                    serverHello.containsExtension(ExtensionType.PSK_KEY_EXCHANGE_MODES),
                    "Server sent a PSK Key Exchange Modes Extension");
            // Servers MUST NOT send a post-handshake CertificateRequest to clients
            // which do not offer this extension.  Servers MUST NOT send this
            // extension.
            assertFalse(
                    serverHello.containsExtension(ExtensionType.POST_HANDSHAKE_AUTH),
                    "Server sent a Post Handshake Auth Extension");
            // The "oid_filters" extension allows servers to provide a set of
            // OID/value pairs which it would like the client's certificate to
            // match.  This extension, if provided by the server, MUST only be sent
            // in the CertificateRequest message.
            assertFalse(
                    serverHello.containsExtension(ExtensionType.OID_FILTERS),
                    "Server sent an OID Filter Extension in Server Hello");
            // Implementations MUST NOT use the Truncated HMAC extension
            assertFalse(
                    serverHello.containsExtension(ExtensionType.TRUNCATED_HMAC),
                    "Server sent a Truncated HMAC Extension");
        }
    }

    public List<DerivationParameter<Config, byte[]>> getTlsVersionsBelow12(DerivationScope scope) {
        List<DerivationParameter<Config, byte[]>> derivationParameters = new LinkedList<>();
        context.getFeatureExtractionResult()
                .getSupportedVersions()
                .forEach(
                        version -> {
                            if (version == ProtocolVersion.TLS10
                                    || version == ProtocolVersion.TLS11) {
                                derivationParameters.add(
                                        new ProtocolVersionDerivation(version.getValue()));
                            }
                        });
        return derivationParameters;
    }
}
