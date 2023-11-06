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
import de.rub.nds.anvilcore.coffee4j.model.ModelFromScope;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.annotations.TlsVersion;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.TlsGenericTest;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@ClientTest
public class Certificate extends TlsGenericTest {

    @Tag("tls12")
    @TlsVersion(supported = ProtocolVersion.TLS12)
    @AnvilTest(id = "XLF-7iivb12njd")
    @KeyExchange(supported = KeyExchangeType.ALL12)
    @ModelFromScope(modelType = "LENGTHFIELD")
    public void certificateMessageLengthTLS12(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = setupLengthFieldTestTls12(argumentAccessor, runner);
        certificateMessagLengthTest(workflowTrace, runner);
    }

    @Tag("tls12")
    @TlsVersion(supported = ProtocolVersion.TLS12)
    @AnvilTest(id = "XLF-eqZYAdwNye")
    @KeyExchange(supported = KeyExchangeType.ALL12)
    @ModelFromScope(modelType = "LENGTHFIELD")
    public void certificateListLengthTLS12(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = setupLengthFieldTestTls12(argumentAccessor, runner);
        certificateListLengthTest(workflowTrace, runner);
    }

    @Tag("tls13")
    @TlsVersion(supported = ProtocolVersion.TLS13)
    @AnvilTest(id = "XLF-uQXeugeUkb")
    @KeyExchange(supported = KeyExchangeType.ALL13)
    @ModelFromScope(modelType = "LENGTHFIELD")
    public void certificateMessageLengthTLS13(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = setupLengthFieldTestTls13(argumentAccessor, runner);
        certificateMessagLengthTest(workflowTrace, runner);
    }

    @Tag("tls13")
    @TlsVersion(supported = ProtocolVersion.TLS13)
    @AnvilTest(id = "XLF-ia3wstdqYe")
    @KeyExchange(supported = KeyExchangeType.ALL13)
    @ModelFromScope(modelType = "LENGTHFIELD")
    public void certificateListLengthTLS13(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = setupLengthFieldTestTls13(argumentAccessor, runner);
        certificateListLengthTest(workflowTrace, runner);
    }

    @Tag("tls13")
    @TlsVersion(supported = ProtocolVersion.TLS13)
    @AnvilTest(id = "XLF-ujMXSAMmVF")
    @KeyExchange(supported = KeyExchangeType.ALL13)
    @ModelFromScope(modelType = "LENGTHFIELD")
    public void certificateRequestContextLength(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = setupLengthFieldTestTls13(argumentAccessor, runner);
        CertificateMessage certificateMessage =
                (CertificateMessage)
                        WorkflowTraceUtil.getFirstSendMessage(
                                HandshakeMessageType.CERTIFICATE, workflowTrace);
        certificateMessage.setRequestContextLength(Modifiable.add(1));
        runner.execute(workflowTrace, runner.getPreparedConfig())
                .validateFinal(super::validateLengthTest);
    }

    private void certificateMessagLengthTest(WorkflowTrace workflowTrace, WorkflowRunner runner) {
        CertificateMessage certificateMessage =
                (CertificateMessage)
                        WorkflowTraceUtil.getFirstSendMessage(
                                HandshakeMessageType.CERTIFICATE, workflowTrace);
        certificateMessage.setLength(Modifiable.sub(1));
        runner.execute(workflowTrace, runner.getPreparedConfig())
                .validateFinal(super::validateLengthTest);
    }

    private void certificateListLengthTest(WorkflowTrace workflowTrace, WorkflowRunner runner) {
        CertificateMessage certificateMessage =
                (CertificateMessage)
                        WorkflowTraceUtil.getFirstSendMessage(
                                HandshakeMessageType.CERTIFICATE, workflowTrace);
        certificateMessage.setCertificatesListLength(Modifiable.sub(1));
        runner.execute(workflowTrace, runner.getPreparedConfig())
                .validateFinal(super::validateLengthTest);
    }
}
