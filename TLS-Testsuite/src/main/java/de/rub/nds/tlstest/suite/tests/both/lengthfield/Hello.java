/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.both.lengthfield;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.DynamicValueConstraints;
import de.rub.nds.anvilcore.coffee4j.model.ModelFromScope;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.annotations.ServerTest;
import de.rub.nds.tlstest.framework.annotations.TlsVersion;
import de.rub.nds.tlstest.framework.annotations.categories.AlertCategory;
import de.rub.nds.tlstest.framework.annotations.categories.HandshakeCategory;
import de.rub.nds.tlstest.framework.annotations.categories.MessageStructureCategory;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.TlsGenericTest;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

public class Hello extends TlsGenericTest {

    @Tag("tls12")
    @TlsVersion(supported = ProtocolVersion.TLS12)
    @AnvilTest(description = "Send a Hello Message with a modified Session ID length value (+1)")
    @KeyExchange(supported = KeyExchangeType.ALL12)
    @ModelFromScope(modelType = "LENGTHFIELD")
    @MessageStructureCategory(SeverityLevel.MEDIUM)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.LOW)
    public void helloSessionIdLengthTLS12(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = setupLengthFieldTestTls12(argumentAccessor, runner);
        sessionIdLengthTest(workflowTrace, runner);
    }

    @Tag("tls13")
    @TlsVersion(supported = ProtocolVersion.TLS13)
    @AnvilTest(description = "Send a Hello Message with a modified Session ID length value (+1)")
    @KeyExchange(supported = KeyExchangeType.ALL13)
    @ModelFromScope(modelType = "LENGTHFIELD")
    @MessageStructureCategory(SeverityLevel.MEDIUM)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.LOW)
    public void helloSessionIdLengthTLS13(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = setupLengthFieldTestTls13(argumentAccessor, runner);
        sessionIdLengthTest(workflowTrace, runner);
    }

    @Tag("tls12")
    @TlsVersion(supported = ProtocolVersion.TLS12)
    @AnvilTest(description = "Send a Hello Message with a modified length value (-1)")
    @KeyExchange(supported = KeyExchangeType.ALL12)
    @ModelFromScope(modelType = "LENGTHFIELD")
    @MessageStructureCategory(SeverityLevel.MEDIUM)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.LOW)
    public void helloLengthTLS12(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = setupLengthFieldTestTls12(argumentAccessor, runner);
        helloLenghtTest(workflowTrace, runner);
    }

    @Tag("tls13")
    @TlsVersion(supported = ProtocolVersion.TLS13)
    @AnvilTest(description = "Send a Hello Message with a modified length value (-1)")
    @KeyExchange(supported = KeyExchangeType.ALL13)
    @ModelFromScope(modelType = "LENGTHFIELD")
    @MessageStructureCategory(SeverityLevel.MEDIUM)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.LOW)
    public void helloLengthTLS13(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = setupLengthFieldTestTls13(argumentAccessor, runner);
        helloLenghtTest(workflowTrace, runner);
    }

    @Tag("tls12")
    @TlsVersion(supported = ProtocolVersion.TLS12)
    @AnvilTest(
            description = "Send a Hello Message with a modified Extension list length value (-1)")
    @KeyExchange(supported = KeyExchangeType.ALL12)
    @ModelFromScope(modelType = "LENGTHFIELD")
    @MessageStructureCategory(SeverityLevel.MEDIUM)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.LOW)
    public void helloExtensionsLengthTLS12(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = setupLengthFieldTestTls12(argumentAccessor, runner);
        helloExtensionsLengthTest(workflowTrace, runner);
    }

    @Tag("tls13")
    @TlsVersion(supported = ProtocolVersion.TLS13)
    @AnvilTest(
            description = "Send a Hello Message with a modified Extension list length value (-1)")
    @KeyExchange(supported = KeyExchangeType.ALL13)
    @ModelFromScope(modelType = "LENGTHFIELD")
    @MessageStructureCategory(SeverityLevel.MEDIUM)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.LOW)
    public void helloExtensionsLengthTLS13(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = setupLengthFieldTestTls13(argumentAccessor, runner);
        helloExtensionsLengthTest(workflowTrace, runner);
    }

    @Tag("tls12")
    @ServerTest
    @TlsVersion(supported = ProtocolVersion.TLS12)
    @AnvilTest(
            description =
                    "Send a Client Hello Message with a modified Cipher Suite list length value (-1)")
    @KeyExchange(supported = KeyExchangeType.ALL12)
    @ModelFromScope(modelType = "LENGTHFIELD")
    @MessageStructureCategory(SeverityLevel.MEDIUM)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.LOW)
    public void clientHelloCipherSuitesLengthTLS12(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = setupLengthFieldTestTls12(argumentAccessor, runner);
        clientHelloCipherSuitesLengthTest(workflowTrace, runner);
    }

    @Tag("tls13")
    @ServerTest
    @TlsVersion(supported = ProtocolVersion.TLS13)
    @AnvilTest(
            description =
                    "Send a Client Hello Message with a modified Cipher Suite list length value (-1)")
    @KeyExchange(supported = KeyExchangeType.ALL13)
    @ModelFromScope(modelType = "LENGTHFIELD")
    @MessageStructureCategory(SeverityLevel.MEDIUM)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.LOW)
    public void clientHelloCipherSuitesLengthTLS13(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = setupLengthFieldTestTls13(argumentAccessor, runner);
        clientHelloCipherSuitesLengthTest(workflowTrace, runner);
    }

    @Tag("tls12")
    @ServerTest
    @TlsVersion(supported = ProtocolVersion.TLS12)
    @AnvilTest(
            description =
                    "Send a Client Hello Message with a modified compression list length value (-1)")
    @KeyExchange(supported = KeyExchangeType.ALL12)
    @ModelFromScope(modelType = "LENGTHFIELD")
    @MessageStructureCategory(SeverityLevel.MEDIUM)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.LOW)
    public void clientHelloCompressionLengthTLS12(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = setupLengthFieldTestTls12(argumentAccessor, runner);
        clientHelloCompressionLengthTest(workflowTrace, runner);
    }

    @Tag("tls13")
    @ServerTest
    @TlsVersion(supported = ProtocolVersion.TLS13)
    @AnvilTest(
            description =
                    "Send a Client Hello Message with a modified compression list length value (-1)")
    @KeyExchange(supported = KeyExchangeType.ALL13)
    @ModelFromScope(modelType = "LENGTHFIELD")
    @MessageStructureCategory(SeverityLevel.MEDIUM)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.LOW)
    public void clientHelloCompressionLengthTLS13(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = setupLengthFieldTestTls13(argumentAccessor, runner);
        clientHelloCompressionLengthTest(workflowTrace, runner);
    }

    private void clientHelloCompressionLengthTest(
            WorkflowTrace workflowTrace, WorkflowRunner runner) {
        ClientHelloMessage helloMessage = (ClientHelloMessage) getHelloMessage(workflowTrace);
        helloMessage.setCompressionLength(Modifiable.sub(1));
        runner.execute(workflowTrace, runner.getPreparedConfig())
                .validateFinal(super::validateLengthTest);
    }

    private void clientHelloCipherSuitesLengthTest(
            WorkflowTrace workflowTrace, WorkflowRunner runner) {
        ClientHelloMessage helloMessage = (ClientHelloMessage) getHelloMessage(workflowTrace);
        helloMessage.setCipherSuiteLength(Modifiable.sub(1));
        runner.execute(workflowTrace, runner.getPreparedConfig())
                .validateFinal(super::validateLengthTest);
    }

    private void helloExtensionsLengthTest(WorkflowTrace workflowTrace, WorkflowRunner runner) {
        if (isClientTest()) {
            separateServerHelloMessage(workflowTrace);
        }
        HelloMessage helloMessage = getHelloMessage(workflowTrace);
        helloMessage.setExtensionsLength(Modifiable.sub(1));
        runner.execute(workflowTrace, runner.getPreparedConfig())
                .validateFinal(super::validateLengthTest);
    }

    private void helloLenghtTest(WorkflowTrace workflowTrace, WorkflowRunner runner) {
        if (isClientTest()) {
            separateServerHelloMessage(workflowTrace);
        }
        HelloMessage helloMessage = getHelloMessage(workflowTrace);
        helloMessage.setLength(Modifiable.sub(1));
        runner.execute(workflowTrace, runner.getPreparedConfig())
                .validateFinal(super::validateLengthTest);
    }

    private void sessionIdLengthTest(WorkflowTrace workflowTrace, WorkflowRunner runner) {
        if (isClientTest()) {
            separateServerHelloMessage(workflowTrace);
        }
        HelloMessage helloMessage = getHelloMessage(workflowTrace);
        helloMessage.setSessionIdLength(Modifiable.add(1));
        runner.execute(workflowTrace, runner.getPreparedConfig())
                .validateFinal(super::validateLengthTest);
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
