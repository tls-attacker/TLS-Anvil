/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * Copyright 2022 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.client.tls13.rfc8701;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.core.protocol.message.EncryptedExtensionsMessage;
import de.rub.nds.tlsattacker.core.protocol.message.NewSessionTicketMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.GreaseExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SupportedVersionsExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.ClientTest;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.ScopeExtensions;
import de.rub.nds.tlstest.framework.annotations.ScopeLimitations;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.annotations.categories.AlertCategory;
import de.rub.nds.tlstest.framework.annotations.categories.CertificateCategory;
import de.rub.nds.tlstest.framework.annotations.categories.ComplianceCategory;
import de.rub.nds.tlstest.framework.annotations.categories.CryptoCategory;
import de.rub.nds.tlstest.framework.annotations.categories.HandshakeCategory;
import de.rub.nds.tlstest.framework.annotations.categories.InteroperabilityCategory;
import de.rub.nds.tlstest.framework.coffee4j.model.ModelFromScope;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.DerivationContainer;
import de.rub.nds.tlstest.framework.model.DerivationType;
import de.rub.nds.tlstest.framework.model.ModelType;
import de.rub.nds.tlstest.framework.model.derivationParameter.GreaseCipherSuiteDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.GreaseExtensionDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.GreaseProtocolVersionDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.GreaseSigHashDerivation;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;

import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@ClientTest
@RFC(number = 8701, section = "4. Server-Initiated Extension Points")
public class ServerInitiatedExtensionPoints extends Tls13Test {

    @TlsTest(description = "When sending a NewSessionTicket message in TLS 1.3, a server "
            + "MAY select one or more GREASE extension values and advertise them as extensions "
            + "with varying length and contents. [...]"
            + "When processing a CertificateRequest or NewSessionTicket, "
            + "clients MUST NOT treat GREASE values differently from any unknown value.")
    @ModelFromScope(baseModel = ModelType.CERTIFICATE)
    @ScopeExtensions(DerivationType.GREASE_EXTENSION)
    @ComplianceCategory(SeverityLevel.MEDIUM)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    public void advertiseGreaseExtensionsInSessionTicket(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        ExtensionType selectedGreaseExt = derivationContainer.getDerivation(GreaseExtensionDerivation.class).getSelectedValue();
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        workflowTrace.addTlsActions(new SendAction(new NewSessionTicketMessage()));

        NewSessionTicketMessage msg = workflowTrace.getFirstSendMessage(NewSessionTicketMessage.class);
        msg.addExtension(new GreaseExtensionMessage(selectedGreaseExt, 25));

        runner.execute(workflowTrace, c).validateFinal(Validator::executedAsPlanned);
    }

    @TlsTest(description = "Clients MUST reject GREASE values when negotiated by the server. "
            + "In particular, the client MUST fail the connection "
            + "if a GREASE value appears in any of the following: "
            + "[...] The \"version\" value in a ServerHello or HelloRetryRequest")
    @ModelFromScope(baseModel = ModelType.CERTIFICATE)
    @ScopeExtensions(DerivationType.GREASE_PROTOCOL_VERSION)
    @ComplianceCategory(SeverityLevel.CRITICAL)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.MEDIUM)
    public void selectGreaseVersion(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsActions(new ReceiveAction(new AlertMessage()));
        sharedGreaseVersionTest(workflowTrace, runner, derivationContainer);
    }

    public static void sharedGreaseVersionTest(WorkflowTrace workflowTrace, WorkflowRunner runner, DerivationContainer externalDerivationContainer) {
        ProtocolVersion selectedGreaseVersion = externalDerivationContainer.getDerivation(GreaseProtocolVersionDerivation.class).getSelectedValue();

        ServerHelloMessage sh = workflowTrace.getFirstSendMessage(ServerHelloMessage.class);
        SupportedVersionsExtensionMessage ext = sh.getExtension(SupportedVersionsExtensionMessage.class);
        ext.setSupportedVersions(Modifiable.explicit(selectedGreaseVersion.getValue()));

        runner.execute(workflowTrace, runner.getPreparedConfig()).validateFinal(Validator::receivedFatalAlert);
    }

    @TlsTest(description = "Clients MUST reject GREASE values when negotiated by the server. "
            + "In particular, the client MUST fail the connection "
            + "if a GREASE value appears in any of the following: "
            + "[...] The \"cipher_suite\" value in a ServerHello")
    @ModelFromScope(baseModel = ModelType.CERTIFICATE)
    @ScopeExtensions(DerivationType.GREASE_CIPHERSUITE)
    @ScopeLimitations(DerivationType.CIPHERSUITE)
    @ComplianceCategory(SeverityLevel.CRITICAL)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.MEDIUM)
    public void selectGreaseCipherSuite(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsActions(new ReceiveAction(new AlertMessage()));
        sharedGreaseCipherSuiteTest(workflowTrace, runner, derivationContainer);
    }

    public static void sharedGreaseCipherSuiteTest(WorkflowTrace workflowTrace, WorkflowRunner runner, DerivationContainer externalDerivationContainer) {
        CipherSuite selectedGreaseCipherSuite = externalDerivationContainer.getDerivation(GreaseCipherSuiteDerivation.class).getSelectedValue();

        ServerHelloMessage sh = workflowTrace.getFirstSendMessage(ServerHelloMessage.class);
        sh.setSelectedCipherSuite(Modifiable.explicit(selectedGreaseCipherSuite.getByteValue()));

        runner.execute(workflowTrace, runner.getPreparedConfig()).validateFinal(Validator::receivedFatalAlert);
    }

    @TlsTest(description = "Clients MUST reject GREASE values when negotiated by the server. "
            + "In particular, the client MUST fail the connection "
            + "if a GREASE value appears in any of the following: "
            + "[...] Any ServerHello extension")
    @ModelFromScope(baseModel = ModelType.CERTIFICATE)
    @ComplianceCategory(SeverityLevel.CRITICAL)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ScopeExtensions(DerivationType.GREASE_EXTENSION)
    @AlertCategory(SeverityLevel.MEDIUM)
    public void sendServerHelloGreaseExtension(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsActions(new ReceiveAction(new AlertMessage()));
        sharedServerHelloGreaseExtensionTest(workflowTrace, runner, derivationContainer);
    }

    public static void sharedServerHelloGreaseExtensionTest(WorkflowTrace workflowTrace, WorkflowRunner runner, DerivationContainer externalDerivationContainer) {
        ExtensionType selectedGreaseExt = externalDerivationContainer.getDerivation(GreaseExtensionDerivation.class).getSelectedValue();

        ServerHelloMessage sh = workflowTrace.getFirstSendMessage(ServerHelloMessage.class);
        sh.addExtension(new GreaseExtensionMessage(selectedGreaseExt, 25));

        runner.execute(workflowTrace, runner.getPreparedConfig()).validateFinal(Validator::receivedFatalAlert);
    }

    @TlsTest(description = "Clients MUST reject GREASE values when negotiated by the server. "
            + "In particular, the client MUST fail the connection "
            + "if a GREASE value appears in any of the following: "
            + "[...] Any HelloRetryRequest, EncryptedExtensions, or Certificate " 
            + "extension in TLS 1.3")
    @ModelFromScope(baseModel = ModelType.CERTIFICATE)
    @ScopeExtensions(DerivationType.GREASE_EXTENSION)
    @ComplianceCategory(SeverityLevel.CRITICAL)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.LOW)
    public void sendEncryptedExtensionsGreaseExtension(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsActions(new ReceiveAction(new AlertMessage()));
        ExtensionType selectedGreaseExt = derivationContainer.getDerivation(GreaseExtensionDerivation.class).getSelectedValue();

        EncryptedExtensionsMessage sh = workflowTrace.getFirstSendMessage(EncryptedExtensionsMessage.class);
        sh.addExtension(new GreaseExtensionMessage(selectedGreaseExt, 25));

        runner.execute(workflowTrace, c).validateFinal(Validator::receivedFatalAlert);
    }

    @TlsTest(description = "Clients MUST reject GREASE values when negotiated by the server. "
            + "In particular, the client MUST fail the connection "
            + "if a GREASE value appears in any of the following: "
            + "[...] The signature algorithm in a server CertificateVerify signature in TLS 1.3")
    @ScopeExtensions(DerivationType.GREASE_SIG_HASH)
    @ComplianceCategory(SeverityLevel.CRITICAL)
    @HandshakeCategory(SeverityLevel.CRITICAL)
    @CryptoCategory(SeverityLevel.CRITICAL)
    @CertificateCategory(SeverityLevel.CRITICAL)
    @AlertCategory(SeverityLevel.LOW)
    public void sendCertificateVerifyGreaseSignatureAlgorithm(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsActions(new ReceiveAction(new AlertMessage()));
        SignatureAndHashAlgorithm selectedGreaseSigHash = derivationContainer.getDerivation(GreaseSigHashDerivation.class).getSelectedValue();

        CertificateVerifyMessage sh = workflowTrace.getFirstSendMessage(CertificateVerifyMessage.class);
        sh.setSignatureHashAlgorithm(Modifiable.explicit(selectedGreaseSigHash.getByteValue()));

        runner.execute(workflowTrace, c).validateFinal(Validator::receivedFatalAlert);
    }
}
