/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.client.tls13.statemachine;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.ClientTest;
import de.rub.nds.anvilcore.annotation.ExcludeParameter;
import de.rub.nds.anvilcore.coffee4j.model.ModelFromScope;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.DeactivateEncryptionAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.SetEncryptChangeCipherSpecConfigAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
import de.rub.nds.tlstest.suite.tests.client.both.statemachine.SharedStateMachineTest;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

/**
 * Contains tests to evaluate the target's state machine. Some test flows are based on results found
 * for TLS 1.2 servers in "Protocol State Fuzzing of TLS Implementations" (de Ruiter et al.)
 */
@Tag("statemachine")
@ClientTest
public class StateMachine extends Tls13Test {

    @AnvilTest
    @ModelFromScope(modelType = "CERTIFICATE")
    public void sendFinishedWithoutCert(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace workflowTrace =
                runner.generateWorkflowTraceUntilSendingMessage(
                        WorkflowTraceType.HELLO, HandshakeMessageType.CERTIFICATE);
        workflowTrace.addTlsActions(
                new SendAction(new FinishedMessage()), new ReceiveAction(new AlertMessage()));

        runner.execute(workflowTrace, c).validateFinal(Validator::receivedFatalAlert);
    }

    @AnvilTest
    @ExcludeParameter("INCLUDE_CHANGE_CIPHER_SPEC")
    @ModelFromScope(modelType = "CERTIFICATE")
    public void sendHandshakeTrafficSecretEncryptedChangeCipherSpec(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        config.setTls13BackwardsCompatibilityMode(true);
        WorkflowTrace workflowTrace =
                runner.generateWorkflowTraceUntilLastSendingMessage(
                        WorkflowTraceType.HELLO, ProtocolMessageType.CHANGE_CIPHER_SPEC);

        workflowTrace.addTlsAction(new SetEncryptChangeCipherSpecConfigAction(true));
        SendAction sendActionEncryptedCCS = new SendAction(new ChangeCipherSpecMessage());

        workflowTrace.addTlsAction(sendActionEncryptedCCS);
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));

        runner.execute(workflowTrace, config).validateFinal(Validator::receivedFatalAlert);
    }

    @AnvilTest
    @ModelFromScope(modelType = "CERTIFICATE")
    public void sendAppTrafficSecretEncryptedChangeCipherSpec(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);

        workflowTrace.addTlsAction(new SetEncryptChangeCipherSpecConfigAction(true));
        SendAction sendActionEncryptedCCS = new SendAction(new ChangeCipherSpecMessage());

        workflowTrace.addTlsAction(sendActionEncryptedCCS);
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));

        runner.execute(workflowTrace, config).validateFinal(Validator::receivedFatalAlert);
    }

    @AnvilTest
    @ModelFromScope(modelType = "CERTIFICATE")
    public void sendLegacyChangeCipherSpecAfterFinished(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        workflowTrace.addTlsAction(new SendAction(new ChangeCipherSpecMessage()));
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));

        runner.execute(workflowTrace, config).validateFinal(Validator::receivedFatalAlert);
    }

    @AnvilTest
    @ModelFromScope(modelType = "CERTIFICATE")
    public void sendLegacyFlowCertificate(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace workflowTrace =
                runner.generateWorkflowTraceUntilSendingMessage(
                        WorkflowTraceType.HELLO, HandshakeMessageType.SERVER_HELLO);
        workflowTrace.addTlsAction(new SendAction(new ServerHelloMessage(config)));
        workflowTrace.addTlsAction(new DeactivateEncryptionAction());
        workflowTrace.addTlsAction(new SendAction(new CertificateMessage()));
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));

        runner.execute(workflowTrace, config).validateFinal(Validator::receivedFatalAlert);
    }

    @AnvilTest
    @ModelFromScope(modelType = "CERTIFICATE")
    public void sendLegacyFlowECDHEKeyExchange(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace workflowTrace =
                runner.generateWorkflowTraceUntilSendingMessage(
                        WorkflowTraceType.HELLO, HandshakeMessageType.SERVER_HELLO);
        workflowTrace.addTlsAction(new SendAction(new ServerHelloMessage(config)));
        workflowTrace.addTlsAction(new DeactivateEncryptionAction());
        workflowTrace.addTlsAction(
                new SendAction(new CertificateMessage(), new ECDHEServerKeyExchangeMessage()));
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));

        runner.execute(workflowTrace, config).validateFinal(Validator::receivedFatalAlert);
    }

    @AnvilTest
    @ModelFromScope(modelType = "CERTIFICATE")
    public void sendLegacyFlowDHEKeyExchange(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace workflowTrace =
                runner.generateWorkflowTraceUntilSendingMessage(
                        WorkflowTraceType.HELLO, HandshakeMessageType.SERVER_HELLO);
        workflowTrace.addTlsAction(new SendAction(new ServerHelloMessage(config)));
        workflowTrace.addTlsAction(new DeactivateEncryptionAction());
        workflowTrace.addTlsAction(
                new SendAction(new CertificateMessage(), new DHEServerKeyExchangeMessage()));
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));

        runner.execute(workflowTrace, config).validateFinal(Validator::receivedFatalAlert);
    }

    @Test
    public void beginWithApplicationData(WorkflowRunner runner) {
        Config config = getConfig();
        SharedStateMachineTest.sharedBeginWithApplicationDataTest(config, runner);
    }

    @Test
    public void beginWithFinished(WorkflowRunner runner) {
        Config config = getConfig();
        SharedStateMachineTest.sharedBeginWithFinishedTest(config, runner);
    }

    @AnvilTest
    public void sendServerHelloTwice(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        SharedStateMachineTest.sharedSendServerHelloTwiceTest(config, runner);
    }

    @AnvilTest
    @ModelFromScope(modelType = "CERTIFICATE")
    public void sendEndOfEarlyDataAsServer(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace workflowTrace =
                runner.generateWorkflowTraceUntilSendingMessage(
                        WorkflowTraceType.HELLO, HandshakeMessageType.FINISHED);
        EndOfEarlyDataMessage endOfEarlyData = new EndOfEarlyDataMessage();
        endOfEarlyData.setAdjustContext(Modifiable.explicit(Boolean.FALSE));
        workflowTrace.addTlsAction(new SendAction(endOfEarlyData));
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));

        runner.execute(workflowTrace, config)
                .validateFinal(
                        i -> {
                            Validator.receivedFatalAlert(i);
                            AlertMessage msg =
                                    i.getWorkflowTrace()
                                            .getFirstReceivedMessage(AlertMessage.class);
                            Validator.testAlertDescription(
                                    i, AlertDescription.UNEXPECTED_MESSAGE, msg);
                        });
    }

    @AnvilTest
    public void omitCertificateVerify(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        WorkflowTrace trace =
                runner.generateWorkflowTraceUntilSendingMessage(
                        WorkflowTraceType.HELLO, HandshakeMessageType.CERTIFICATE_VERIFY);
        trace.addTlsActions(
                new SendAction(new FinishedMessage()), new ReceiveAction(new AlertMessage()));

        runner.execute(trace, c).validateFinal(Validator::receivedFatalAlert);
    }
}
