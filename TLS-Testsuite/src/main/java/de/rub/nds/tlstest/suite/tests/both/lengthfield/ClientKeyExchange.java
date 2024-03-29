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
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ClientKeyExchangeMessage;
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
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@ServerTest
@Tag("tls12")
@TlsVersion(supported = {ProtocolVersion.TLS12, ProtocolVersion.DTLS12})
@KeyExchange(supported = KeyExchangeType.ALL12)
public class ClientKeyExchange extends TlsLengthfieldTest {

    @AnvilTest(id = "XLF-4iPUuT51YH")
    @TlsVersion(
            supported =
                    ProtocolVersion
                            .TLS12) // TODO: adapt DTLS layer to retain message length modification
    @ModelFromScope(modelType = "LENGTHFIELD")
    public void clientKeyExchangeLength(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        WorkflowTrace workflowTrace =
                getWorkflowTraceSeparatedClientKeyExchange(argumentAccessor, runner);
        ClientKeyExchangeMessage clientKeyExchange =
                (ClientKeyExchangeMessage)
                        WorkflowTraceUtil.getFirstSendMessage(
                                HandshakeMessageType.CLIENT_KEY_EXCHANGE, workflowTrace);
        clientKeyExchange.setLength(Modifiable.sub(1));
        runner.execute(workflowTrace, runner.getPreparedConfig())
                .validateFinal(super::validateLengthTest);
    }

    @AnvilTest(id = "XLF-NFYNXBgXk8")
    @ModelFromScope(modelType = "LENGTHFIELD")
    public void clientKeyExchangePublicKeyLength(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        WorkflowTrace workflowTrace =
                getWorkflowTraceSeparatedClientKeyExchange(argumentAccessor, runner);
        ClientKeyExchangeMessage clientKeyExchange =
                (ClientKeyExchangeMessage)
                        WorkflowTraceUtil.getFirstSendMessage(
                                HandshakeMessageType.CLIENT_KEY_EXCHANGE, workflowTrace);
        clientKeyExchange.setPublicKeyLength(Modifiable.sub(1));
        runner.execute(workflowTrace, runner.getPreparedConfig())
                .validateFinal(super::validateLengthTest);
    }

    private WorkflowTrace getWorkflowTraceSeparatedClientKeyExchange(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        WorkflowTrace workflowTrace = setupLengthFieldTestTls12(argumentAccessor, runner);
        SendAction sendCkeCcsFin =
                (SendAction)
                        WorkflowTraceUtil.getFirstSendingActionForMessage(
                                HandshakeMessageType.CLIENT_KEY_EXCHANGE, workflowTrace);
        ClientKeyExchangeMessage clientKeyExchange =
                (ClientKeyExchangeMessage)
                        WorkflowTraceUtil.getFirstSendMessage(
                                HandshakeMessageType.CLIENT_KEY_EXCHANGE, workflowTrace);
        sendCkeCcsFin.getSendMessages().remove(clientKeyExchange);
        sendCkeCcsFin.addActionOption(ActionOption.MAY_FAIL);
        workflowTrace
                .getTlsActions()
                .add(
                        workflowTrace.getTlsActions().indexOf(sendCkeCcsFin),
                        new SendAction(clientKeyExchange));
        return workflowTrace;
    }
}
