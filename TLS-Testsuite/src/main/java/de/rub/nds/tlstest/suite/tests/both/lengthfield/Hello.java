/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.both.lengthfield;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.ServerTest;
import de.rub.nds.anvilcore.coffee4j.model.ModelFromScope;
import de.rub.nds.anvilcore.teststate.AnvilTestCase;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.annotations.TlsVersion;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.TlsLengthfieldTest;
import org.junit.jupiter.api.Tag;

public class Hello extends TlsLengthfieldTest {

    @Tag("tls12")
    @TlsVersion(supported = {ProtocolVersion.TLS12, ProtocolVersion.DTLS12})
    @AnvilTest(id = "XLF-anjpbghN69")
    @KeyExchange(supported = KeyExchangeType.ALL12)
    @ModelFromScope(modelType = "LENGTHFIELD")
    public void helloSessionIdLengthTLS12(AnvilTestCase testCase, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = setupLengthFieldTestTls12(runner);
        sessionIdLengthTest(workflowTrace, runner, testCase);
    }

    @Tag("tls13")
    @TlsVersion(supported = ProtocolVersion.TLS13)
    @AnvilTest(id = "XLF-c4Db7ctU7V")
    @KeyExchange(supported = KeyExchangeType.ALL13)
    @ModelFromScope(modelType = "LENGTHFIELD")
    public void helloSessionIdLengthTLS13(AnvilTestCase testCase, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = setupLengthFieldTestTls13(runner);
        sessionIdLengthTest(workflowTrace, runner, testCase);
    }

    @Tag("tls12")
    @TlsVersion(
            supported =
                    ProtocolVersion
                            .TLS12) // TODO: adapt DTLS layer to retain message length modification
    @AnvilTest(id = "XLF-7AdFFavtAd")
    @KeyExchange(supported = KeyExchangeType.ALL12)
    @ModelFromScope(modelType = "LENGTHFIELD")
    public void helloLengthTLS12(AnvilTestCase testCase, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = setupLengthFieldTestTls12(runner);
        helloLenghtTest(workflowTrace, runner, testCase);
    }

    @Tag("tls13")
    @TlsVersion(supported = ProtocolVersion.TLS13)
    @AnvilTest(id = "XLF-RUoZsBa3n4")
    @KeyExchange(supported = KeyExchangeType.ALL13)
    @ModelFromScope(modelType = "LENGTHFIELD")
    public void helloLengthTLS13(AnvilTestCase testCase, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = setupLengthFieldTestTls13(runner);
        helloLenghtTest(workflowTrace, runner, testCase);
    }

    @Tag("tls12")
    @TlsVersion(supported = {ProtocolVersion.TLS12, ProtocolVersion.DTLS12})
    @AnvilTest(id = "XLF-8NkdoEnnup")
    @KeyExchange(supported = KeyExchangeType.ALL12)
    @ModelFromScope(modelType = "LENGTHFIELD")
    public void helloExtensionsLengthTLS12(AnvilTestCase testCase, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = setupLengthFieldTestTls12(runner);
        helloExtensionsLengthTest(workflowTrace, runner, testCase);
    }

    @Tag("tls13")
    @TlsVersion(supported = ProtocolVersion.TLS13)
    @AnvilTest(id = "XLF-hjh8QDJmvK")
    @KeyExchange(supported = KeyExchangeType.ALL13)
    @ModelFromScope(modelType = "LENGTHFIELD")
    public void helloExtensionsLengthTLS13(AnvilTestCase testCase, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = setupLengthFieldTestTls13(runner);
        helloExtensionsLengthTest(workflowTrace, runner, testCase);
    }

    @Tag("tls12")
    @ServerTest
    @TlsVersion(supported = {ProtocolVersion.TLS12, ProtocolVersion.DTLS12})
    @AnvilTest(id = "XLF-9XEqy2ZCoa")
    @KeyExchange(supported = KeyExchangeType.ALL12)
    @ModelFromScope(modelType = "LENGTHFIELD")
    public void clientHelloCipherSuitesLengthTLS12(AnvilTestCase testCase, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = setupLengthFieldTestTls12(runner);
        clientHelloCipherSuitesLengthTest(workflowTrace, runner, testCase);
    }

    @Tag("tls13")
    @ServerTest
    @TlsVersion(supported = ProtocolVersion.TLS13)
    @AnvilTest(id = "XLF-rUWM4KWG2t")
    @KeyExchange(supported = KeyExchangeType.ALL13)
    @ModelFromScope(modelType = "LENGTHFIELD")
    public void clientHelloCipherSuitesLengthTLS13(AnvilTestCase testCase, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = setupLengthFieldTestTls13(runner);
        clientHelloCipherSuitesLengthTest(workflowTrace, runner, testCase);
    }

    @Tag("tls12")
    @ServerTest
    @TlsVersion(supported = {ProtocolVersion.TLS12, ProtocolVersion.DTLS12})
    @AnvilTest(id = "XLF-2BCMFwzm2j")
    @KeyExchange(supported = KeyExchangeType.ALL12)
    @ModelFromScope(modelType = "LENGTHFIELD")
    public void clientHelloCompressionLengthTLS12(AnvilTestCase testCase, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = setupLengthFieldTestTls12(runner);
        clientHelloCompressionLengthTest(workflowTrace, runner, testCase);
    }

    @Tag("tls13")
    @ServerTest
    @TlsVersion(supported = ProtocolVersion.TLS13)
    @AnvilTest(id = "XLF-pR3iFN7Miv")
    @KeyExchange(supported = KeyExchangeType.ALL13)
    @ModelFromScope(modelType = "LENGTHFIELD")
    public void clientHelloCompressionLengthTLS13(AnvilTestCase testCase, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = setupLengthFieldTestTls13(runner);
        clientHelloCompressionLengthTest(workflowTrace, runner, testCase);
    }

    private void clientHelloCompressionLengthTest(
            WorkflowTrace workflowTrace, WorkflowRunner runner, AnvilTestCase testCase) {
        ClientHelloMessage helloMessage = (ClientHelloMessage) getHelloMessage(workflowTrace);
        helloMessage.setCompressionLength(Modifiable.sub(1));
        State state = runner.execute(workflowTrace, runner.getPreparedConfig());
        validateLengthTest(state, testCase);
    }

    private void clientHelloCipherSuitesLengthTest(
            WorkflowTrace workflowTrace, WorkflowRunner runner, AnvilTestCase testCase) {
        ClientHelloMessage helloMessage = (ClientHelloMessage) getHelloMessage(workflowTrace);
        helloMessage.setCipherSuiteLength(Modifiable.sub(1));
        State state = runner.execute(workflowTrace, runner.getPreparedConfig());
        validateLengthTest(state, testCase);
    }

    private void helloExtensionsLengthTest(
            WorkflowTrace workflowTrace, WorkflowRunner runner, AnvilTestCase testCase) {
        if (isClientTest()) {
            separateServerHelloMessage(workflowTrace);
        }
        HelloMessage helloMessage = getHelloMessage(workflowTrace);
        helloMessage.setExtensionsLength(Modifiable.sub(1));
        State state = runner.execute(workflowTrace, runner.getPreparedConfig());
        validateLengthTest(state, testCase);
    }

    private void helloLenghtTest(
            WorkflowTrace workflowTrace, WorkflowRunner runner, AnvilTestCase testCase) {
        if (isClientTest()) {
            separateServerHelloMessage(workflowTrace);
        }
        HelloMessage helloMessage = getHelloMessage(workflowTrace);
        helloMessage.setLength(Modifiable.sub(1));
        State state = runner.execute(workflowTrace, runner.getPreparedConfig());
        validateLengthTest(state, testCase);
    }

    private void sessionIdLengthTest(
            WorkflowTrace workflowTrace, WorkflowRunner runner, AnvilTestCase testCase) {
        if (isClientTest()) {
            separateServerHelloMessage(workflowTrace);
        }
        HelloMessage helloMessage = getHelloMessage(workflowTrace);
        helloMessage.setSessionIdLength(Modifiable.add(1));
        State state = runner.execute(workflowTrace, runner.getPreparedConfig());
        validateLengthTest(state, testCase);
    }

    private HelloMessage getHelloMessage(WorkflowTrace workflowTrace) {
        HandshakeMessage helloMessage;
        if (isClientTest()) {
            helloMessage =
                    WorkflowTraceUtil.getFirstSendMessage(
                            HandshakeMessageType.SERVER_HELLO, workflowTrace);
        } else {
            helloMessage =
                    WorkflowTraceUtil.getFirstSendMessage(
                            HandshakeMessageType.CLIENT_HELLO, workflowTrace);
        }
        return (HelloMessage) helloMessage;
    }

    private void separateServerHelloMessage(WorkflowTrace workflowTrace) {
        ServerHelloMessage serverHello =
                (ServerHelloMessage)
                        WorkflowTraceUtil.getFirstSendMessage(
                                HandshakeMessageType.SERVER_HELLO, workflowTrace);
        SendAction sendServerHelloMessages =
                (SendAction)
                        WorkflowTraceUtil.getFirstSendingActionForMessage(
                                HandshakeMessageType.SERVER_HELLO, workflowTrace);
        sendServerHelloMessages.getSendMessages().remove(serverHello);
        sendServerHelloMessages.addActionOption(ActionOption.MAY_FAIL);
        workflowTrace.addTlsAction(
                workflowTrace.getTlsActions().indexOf(sendServerHelloMessages),
                new SendAction(serverHello));
    }
}
