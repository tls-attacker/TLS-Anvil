/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.client.tls13.statemachine;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.ExcludeParameter;
import de.rub.nds.anvilcore.annotation.TestDescription;
import de.rub.nds.anvilcore.coffee4j.model.ModelFromScope;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.DHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.EndOfEarlyDataMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.DeactivateEncryptionAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.SetEncryptChangeCipherSpecConfigAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.ClientTest;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.categories.AlertCategory;
import de.rub.nds.tlstest.framework.annotations.categories.CVECategory;
import de.rub.nds.tlstest.framework.annotations.categories.CertificateCategory;
import de.rub.nds.tlstest.framework.annotations.categories.ComplianceCategory;
import de.rub.nds.tlstest.framework.annotations.categories.CryptoCategory;
import de.rub.nds.tlstest.framework.annotations.categories.HandshakeCategory;
import de.rub.nds.tlstest.framework.annotations.categories.SecurityCategory;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
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

    @AnvilTest(description = "CVE-2020-24613, Send Finished without Certificate")
    @HandshakeCategory(SeverityLevel.CRITICAL)
    @ComplianceCategory(SeverityLevel.CRITICAL)
    @SecurityCategory(SeverityLevel.CRITICAL)
    @CVECategory(SeverityLevel.CRITICAL)
    @ModelFromScope(modelType = "CERTIFICATE")
    @AlertCategory(SeverityLevel.LOW)
    public void sendFinishedWithoutCert(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace workflowTrace =
                runner.generateWorkflowTraceUntilSendingMessage(
                        WorkflowTraceType.HELLO, HandshakeMessageType.CERTIFICATE);
        workflowTrace.addTlsActions(
                new SendAction(new FinishedMessage()), new ReceiveAction(new AlertMessage()));

        runner.execute(workflowTrace, c).validateFinal(Validator::receivedFatalAlert);
    }

    @AnvilTest(
            description =
                    "An "
                            + "implementation which receives any other change_cipher_spec value or "
                            + "which receives a protected change_cipher_spec record MUST abort the "
                            + "handshake with an \"unexpected_message\" alert.")
    @RFC(number = 8446, section = "5. Record Protocol")
    @ExcludeParameter("INCLUDE_CHANGE_CIPHER_SPEC")
    @ModelFromScope(modelType = "CERTIFICATE")
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.LOW)
    @ComplianceCategory(SeverityLevel.MEDIUM)
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

    @AnvilTest(
            description =
                    "An "
                            + "implementation which receives any other change_cipher_spec value or "
                            + "which receives a protected change_cipher_spec record MUST abort the "
                            + "handshake with an \"unexpected_message\" alert.")
    @RFC(number = 8446, section = "5. Record Protocol")
    @ModelFromScope(modelType = "CERTIFICATE")
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.LOW)
    @ComplianceCategory(SeverityLevel.MEDIUM)
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

    @AnvilTest(
            description =
                    "If an implementation "
                            + "detects a change_cipher_spec record received before the first "
                            + "ClientHello message or after the peer's Finished message, it MUST be "
                            + "treated as an unexpected record type (though stateless servers may "
                            + "not be able to distinguish these cases from allowed cases).")
    @RFC(number = 8446, section = "5. Record Protocol")
    @ModelFromScope(modelType = "CERTIFICATE")
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.LOW)
    public void sendLegacyChangeCipherSpecAfterFinished(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        workflowTrace.addTlsAction(new SendAction(new ChangeCipherSpecMessage()));
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));

        runner.execute(workflowTrace, config).validateFinal(Validator::receivedFatalAlert);
    }

    @AnvilTest(description = "Negotiate TLS 1.3 but send an unencrypted Certificate Message")
    @ModelFromScope(modelType = "CERTIFICATE")
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    @SecurityCategory(SeverityLevel.HIGH)
    @AlertCategory(SeverityLevel.LOW)
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

    @AnvilTest(
            description =
                    "Negotiate TLS 1.3 but send an unencrypted Certificate Message and legacy ECDHE Key Exchange Message")
    @ModelFromScope(modelType = "CERTIFICATE")
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    @SecurityCategory(SeverityLevel.HIGH)
    @AlertCategory(SeverityLevel.LOW)
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

    @AnvilTest(
            description =
                    "Negotiate TLS 1.3 but send an unencrypted Certificate Message and legacy DHE Key Exchange Message")
    @ModelFromScope(modelType = "CERTIFICATE")
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    @SecurityCategory(SeverityLevel.HIGH)
    @AlertCategory(SeverityLevel.LOW)
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
    @TestDescription("Begin the Handshake with an Application Data Message")
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    @SecurityCategory(SeverityLevel.CRITICAL)
    @AlertCategory(SeverityLevel.LOW)
    public void beginWithApplicationData(WorkflowRunner runner) {
        Config config = getConfig();
        SharedStateMachineTest.sharedBeginWithApplicationDataTest(config, runner);
    }

    @Test
    @TestDescription("Begin the Handshake with a Finished Message")
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    @SecurityCategory(SeverityLevel.CRITICAL)
    @AlertCategory(SeverityLevel.MEDIUM)
    public void beginWithFinished(WorkflowRunner runner) {
        Config config = getConfig();
        SharedStateMachineTest.sharedBeginWithFinishedTest(config, runner);
    }

    @AnvilTest(description = "Send a second encrypted Server Hello")
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.CRITICAL)
    @SecurityCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.LOW)
    public void sendServerHelloTwice(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        SharedStateMachineTest.sharedSendServerHelloTwiceTest(config, runner);
    }

    @RFC(number = 8446, section = "4.5. End of Early Data")
    @AnvilTest(
            description =
                    "Servers MUST NOT send this message, and clients receiving it MUST "
                            + "terminate the connection with an \"unexpected_message\" alert.")
    @ModelFromScope(modelType = "CERTIFICATE")
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
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

    @RFC(number = 8446, section = "4.4.3. Certificate Verify")
    @AnvilTest(
            description = "Servers MUST send this message when authenticating via a certificate.")
    @SecurityCategory(SeverityLevel.CRITICAL)
    @CryptoCategory(SeverityLevel.CRITICAL)
    @CertificateCategory(SeverityLevel.CRITICAL)
    @AlertCategory(SeverityLevel.LOW)
    @ComplianceCategory(SeverityLevel.HIGH)
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
