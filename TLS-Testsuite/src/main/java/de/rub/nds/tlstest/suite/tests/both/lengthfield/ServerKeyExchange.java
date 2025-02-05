/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.both.lengthfield;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.ClientTest;
import de.rub.nds.anvilcore.annotation.DynamicValueConstraints;
import de.rub.nds.anvilcore.coffee4j.model.ModelFromScope;
import de.rub.nds.anvilcore.teststate.AnvilTestCase;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.DHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceResultUtil;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.annotations.TlsVersion;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.TlsLengthfieldTest;
import org.junit.jupiter.api.Tag;

@ClientTest
@Tag("tls12")
@TlsVersion(supported = {ProtocolVersion.TLS12, ProtocolVersion.DTLS12})
@KeyExchange(supported = KeyExchangeType.ALL12, requiresServerKeyExchMsg = true)
public class ServerKeyExchange extends TlsLengthfieldTest {

    @AnvilTest(id = "XLF-Z5CqDTjvni")
    @TlsVersion(
            supported =
                    ProtocolVersion
                            .TLS12) // TODO: adapt DTLS layer to retain message length modification
    @ModelFromScope(modelType = "LENGTHFIELD")
    public void serverKeyExchangeLength(AnvilTestCase testCase, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = setupLengthFieldTestTls12(runner);
        ServerKeyExchangeMessage serverKeyExchange =
                (ServerKeyExchangeMessage)
                        WorkflowTraceResultUtil.getFirstSentMessage(
                                workflowTrace, HandshakeMessageType.SERVER_KEY_EXCHANGE);
        serverKeyExchange.setLength(Modifiable.sub(1));
        State state = runner.execute(workflowTrace, runner.getPreparedConfig());
        validateLengthTest(state, testCase);
    }

    @AnvilTest(id = "XLF-gvZTTfnQTn")
    @ModelFromScope(modelType = "LENGTHFIELD")
    @DynamicValueConstraints(
            affectedIdentifiers = "CIPHER_SUITE",
            methods = "isNotAnonymousCipherSuite")
    public void serverKeyExchangeSignatureLength(AnvilTestCase testCase, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = setupLengthFieldTestTls12(runner);
        ServerKeyExchangeMessage serverKeyExchange =
                (ServerKeyExchangeMessage)
                        WorkflowTraceResultUtil.getFirstSentMessage(
                                workflowTrace, HandshakeMessageType.SERVER_KEY_EXCHANGE);
        serverKeyExchange.setSignatureLength(Modifiable.sub(1));
        State state = runner.execute(workflowTrace, runner.getPreparedConfig());
        validateLengthTest(state, testCase);
    }

    @AnvilTest(id = "XLF-yiZVhouStn")
    @ModelFromScope(modelType = "LENGTHFIELD")
    public void serverKeyExchangePublicKeyLength(AnvilTestCase testCase, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = setupLengthFieldTestTls12(runner);
        ServerKeyExchangeMessage serverKeyExchange =
                (ServerKeyExchangeMessage)
                        WorkflowTraceResultUtil.getFirstSentMessage(
                                workflowTrace, HandshakeMessageType.SERVER_KEY_EXCHANGE);
        serverKeyExchange.setPublicKeyLength(Modifiable.sub(1));
        State state = runner.execute(workflowTrace, runner.getPreparedConfig());
        validateLengthTest(state, testCase);
    }

    @AnvilTest(id = "XLF-8852p34nEP")
    @ModelFromScope(modelType = "LENGTHFIELD")
    @KeyExchange(supported = KeyExchangeType.DH, requiresServerKeyExchMsg = true)
    public void modulusLength(AnvilTestCase testCase, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = setupLengthFieldTestTls12(runner);
        DHEServerKeyExchangeMessage serverKeyExchange =
                (DHEServerKeyExchangeMessage)
                        WorkflowTraceResultUtil.getFirstSentMessage(
                                workflowTrace, HandshakeMessageType.SERVER_KEY_EXCHANGE);
        serverKeyExchange.setModulusLength(Modifiable.sub(1));
        State state = runner.execute(workflowTrace, runner.getPreparedConfig());
        validateLengthTest(state, testCase);
    }

    @AnvilTest(id = "XLF-DVpNzSiTq5")
    @ModelFromScope(modelType = "LENGTHFIELD")
    @KeyExchange(supported = KeyExchangeType.DH, requiresServerKeyExchMsg = true)
    public void generatorLength(AnvilTestCase testCase, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = setupLengthFieldTestTls12(runner);
        DHEServerKeyExchangeMessage serverKeyExchange =
                (DHEServerKeyExchangeMessage)
                        WorkflowTraceResultUtil.getFirstSentMessage(
                                workflowTrace, HandshakeMessageType.SERVER_KEY_EXCHANGE);
        serverKeyExchange.setGeneratorLength(Modifiable.sub(1));
        State state = runner.execute(workflowTrace, runner.getPreparedConfig());
        validateLengthTest(state, testCase);
    }

    public boolean isNotAnonymousCipherSuite(CipherSuite cipherSuite) {
        return !cipherSuite.isAnon();
    }
}
