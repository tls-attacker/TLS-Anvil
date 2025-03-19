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
import de.rub.nds.tlsattacker.core.protocol.message.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceConfigurationUtil;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.annotations.TlsVersion;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.TlsLengthfieldTest;
import org.junit.jupiter.api.Tag;

/** */
@ClientTest
@Tag("tls13")
@TlsVersion(supported = ProtocolVersion.TLS13)
@KeyExchange(supported = KeyExchangeType.ALL13)
public class CertificateVerify extends TlsLengthfieldTest {

    @AnvilTest(id = "XLF-tSjRqK81S8")
    @ModelFromScope(modelType = "LENGTHFIELD")
    public void certificateVerifyLength(AnvilTestCase testCase, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = setupLengthFieldTestTls13(runner);
        CertificateVerifyMessage certVerifyMsg =
                (CertificateVerifyMessage)
                        WorkflowTraceConfigurationUtil.getFirstStaticConfiguredSendMessage(
                                workflowTrace, HandshakeMessageType.CERTIFICATE_VERIFY);
        certVerifyMsg.setLength(Modifiable.sub(1));
        State state = runner.execute(workflowTrace, runner.getPreparedConfig());
        validateLengthTest(state, testCase);
    }

    @AnvilTest(id = "XLF-PkwVF7pRQa")
    @ModelFromScope(modelType = "LENGTHFIELD")
    public void certificateVerifySignatureLength(AnvilTestCase testCase, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = setupLengthFieldTestTls13(runner);
        CertificateVerifyMessage certVerifyMsg =
                (CertificateVerifyMessage)
                        WorkflowTraceConfigurationUtil.getFirstStaticConfiguredSendMessage(
                                workflowTrace, HandshakeMessageType.CERTIFICATE_VERIFY);
        certVerifyMsg.setSignatureLength(Modifiable.sub(1));
        State state = runner.execute(workflowTrace, runner.getPreparedConfig());
        validateLengthTest(state, testCase);
    }
}
