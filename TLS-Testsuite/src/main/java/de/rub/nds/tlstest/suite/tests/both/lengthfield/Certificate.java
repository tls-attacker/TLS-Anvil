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
import de.rub.nds.anvilcore.teststate.AnvilTestCase;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
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
public class Certificate extends TlsLengthfieldTest {

    @Tag("tls12")
    @TlsVersion(
            supported = {
                ProtocolVersion.TLS12
            }) // TODO: adapt DTLS layer to retain message length modification
    @AnvilTest(id = "XLF-7iivb12njd")
    @KeyExchange(supported = KeyExchangeType.ALL12)
    @ModelFromScope(modelType = "LENGTHFIELD")
    public void certificateMessageLengthTLS12(AnvilTestCase testCase, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = setupLengthFieldTestTls12(runner);
        certificateMessagLengthTest(workflowTrace, runner, testCase);
    }

    @Tag("tls12")
    @TlsVersion(supported = {ProtocolVersion.TLS12, ProtocolVersion.DTLS12})
    @AnvilTest(id = "XLF-eqZYAdwNye")
    @KeyExchange(supported = KeyExchangeType.ALL12)
    @ModelFromScope(modelType = "LENGTHFIELD")
    public void certificateListLengthTLS12(AnvilTestCase testCase, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = setupLengthFieldTestTls12(runner);
        certificateListLengthTest(workflowTrace, runner, testCase);
    }

    @Tag("tls13")
    @TlsVersion(supported = ProtocolVersion.TLS13)
    @AnvilTest(id = "XLF-uQXeugeUkb")
    @KeyExchange(supported = KeyExchangeType.ALL13)
    @ModelFromScope(modelType = "LENGTHFIELD")
    public void certificateMessageLengthTLS13(AnvilTestCase testCase, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = setupLengthFieldTestTls13(runner);
        certificateMessagLengthTest(workflowTrace, runner, testCase);
    }

    @Tag("tls13")
    @TlsVersion(supported = ProtocolVersion.TLS13)
    @AnvilTest(id = "XLF-ia3wstdqYe")
    @KeyExchange(supported = KeyExchangeType.ALL13)
    @ModelFromScope(modelType = "LENGTHFIELD")
    public void certificateListLengthTLS13(AnvilTestCase testCase, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = setupLengthFieldTestTls13(runner);
        certificateListLengthTest(workflowTrace, runner, testCase);
    }

    @Tag("tls13")
    @TlsVersion(supported = ProtocolVersion.TLS13)
    @AnvilTest(id = "XLF-ujMXSAMmVF")
    @KeyExchange(supported = KeyExchangeType.ALL13)
    @ModelFromScope(modelType = "LENGTHFIELD")
    public void certificateRequestContextLength(AnvilTestCase testCase, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = setupLengthFieldTestTls13(runner);
        CertificateMessage certificateMessage =
                (CertificateMessage)
                        WorkflowTraceResultUtil.getFirstSentMessage(
                                workflowTrace, HandshakeMessageType.CERTIFICATE);
        certificateMessage.setRequestContextLength(Modifiable.add(1));
        State state = runner.execute(workflowTrace, runner.getPreparedConfig());
        validateLengthTest(state, testCase);
    }

    private void certificateMessagLengthTest(
            WorkflowTrace workflowTrace, WorkflowRunner runner, AnvilTestCase testCase) {
        CertificateMessage certificateMessage =
                (CertificateMessage)
                        WorkflowTraceResultUtil.getFirstSentMessage(
                                workflowTrace, HandshakeMessageType.CERTIFICATE);
        certificateMessage.setLength(Modifiable.sub(1));
        State state = runner.execute(workflowTrace, runner.getPreparedConfig());
        validateLengthTest(state, testCase);
    }

    private void certificateListLengthTest(
            WorkflowTrace workflowTrace, WorkflowRunner runner, AnvilTestCase testCase) {
        CertificateMessage certificateMessage =
                (CertificateMessage)
                        WorkflowTraceResultUtil.getFirstSentMessage(
                                workflowTrace, HandshakeMessageType.CERTIFICATE);
        certificateMessage.setCertificatesListLength(Modifiable.sub(1));
        State state = runner.execute(workflowTrace, runner.getPreparedConfig());
        validateLengthTest(state, testCase);
    }
}
