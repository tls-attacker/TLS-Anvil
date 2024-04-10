/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.both.lengthfield;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.MethodCondition;
import de.rub.nds.anvilcore.coffee4j.model.ModelFromScope;
import de.rub.nds.anvilcore.constants.TestEndpointType;
import de.rub.nds.anvilcore.teststate.AnvilTestCase;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.annotations.TlsVersion;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.TlsLengthfieldTest;
import de.rub.nds.tlstest.suite.util.DtlsTestConditions;
import org.junit.jupiter.api.Tag;

public class Finished extends TlsLengthfieldTest {

    @Tag("tls12")
    @TlsVersion(
            supported =
                    ProtocolVersion
                            .TLS12) // TODO: adapt DTLS layer to retain message length modification
    @AnvilTest(id = "XLF-CSQn3dUG9L")
    @KeyExchange(supported = KeyExchangeType.ALL12)
    @ModelFromScope(modelType = "LENGTHFIELD")
    // no response to server's FIN is ambiguous in DTLS if no app data is sent by client
    @MethodCondition(clazz = DtlsTestConditions.class, method = "isServerTestOrClientSendsAppData")
    public void finishedLengthTLS12(AnvilTestCase testCase, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = setupLengthFieldTestTls12(runner);
        finishedLengthTest(workflowTrace, runner, testCase);
    }

    @Tag("tls13")
    @TlsVersion(supported = ProtocolVersion.TLS13)
    @AnvilTest(id = "XLF-CALCiXbvRo")
    @KeyExchange(supported = KeyExchangeType.ALL13)
    @ModelFromScope(modelType = "LENGTHFIELD")
    public void finishedLengthTLS13(AnvilTestCase testCase, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = setupLengthFieldTestTls13(runner);
        finishedLengthTest(workflowTrace, runner, testCase);
    }

    private void finishedLengthTest(
            WorkflowTrace workflowTrace, WorkflowRunner runner, AnvilTestCase testCase) {
        FinishedMessage finishedMessage =
                (FinishedMessage)
                        WorkflowTraceUtil.getFirstSendMessage(
                                HandshakeMessageType.FINISHED, workflowTrace);
        finishedMessage.setLength(Modifiable.sub(1));
        if ((runner.getPreparedConfig().getHighestProtocolVersion() != ProtocolVersion.TLS13
                        && context.getConfig().getTestEndpointMode() == TestEndpointType.CLIENT)
                || (runner.getPreparedConfig().getHighestProtocolVersion() == ProtocolVersion.TLS13
                        && context.getConfig().getTestEndpointMode() == TestEndpointType.SERVER)) {
            workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));
            State state = runner.execute(workflowTrace, runner.getPreparedConfig());
            Validator.receivedFatalAlert(state, testCase);
        } else {
            State state = runner.execute(workflowTrace, runner.getPreparedConfig());
            validateLengthTest(state, testCase);
        }
    }
}
