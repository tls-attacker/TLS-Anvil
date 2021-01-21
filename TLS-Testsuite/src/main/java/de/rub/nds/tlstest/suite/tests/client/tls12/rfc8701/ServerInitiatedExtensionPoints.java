/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.client.tls12.rfc8701;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.GreaseExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.ClientTest;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.ScopeExtensions;
import de.rub.nds.tlstest.framework.annotations.ScopeLimitations;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.annotations.categories.Alert;
import de.rub.nds.tlstest.framework.annotations.categories.Compliance;
import de.rub.nds.tlstest.framework.annotations.categories.Handshake;
import de.rub.nds.tlstest.framework.annotations.categories.Interoperability;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.DerivationType;
import de.rub.nds.tlstest.framework.model.derivationParameter.GreaseCipherSuiteDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.GreaseExtensionDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.GreaseNamedGroupDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.GreaseProtocolVersionDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.GreaseSigHashDerivation;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@ClientTest
@RFC(number = 8701, section = "4. Server-Initiated Extension Points")
public class ServerInitiatedExtensionPoints extends Tls12Test {

    @TlsTest(description = "Clients MUST reject GREASE values when negotiated by the server. "
            + "In particular, the client MUST fail the connection "
            + "if a GREASE value appears in any of the following: "
            + "The \"version\" value in a ServerHello or HelloRetryRequest")
    @ScopeExtensions(DerivationType.GREASE_PROTOCOL_VERSION)
    @Handshake(SeverityLevel.MEDIUM)
    @Interoperability(SeverityLevel.HIGH)
    /*Categories MM: Here I'd also argue that this does not affect interop.
    (same for all tests below)*/
    @Alert(SeverityLevel.MEDIUM)
    public void selectGreaseVersion(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsActions(new ReceiveAction(new AlertMessage()));

        ProtocolVersion greaseVersion = derivationContainer.getDerivation(GreaseProtocolVersionDerivation.class).getSelectedValue();
        ServerHelloMessage sh = workflowTrace.getFirstSendMessage(ServerHelloMessage.class);
        sh.setProtocolVersion(Modifiable.explicit(greaseVersion.getValue()));

        runner.execute(workflowTrace, c).validateFinal(Validator::receivedFatalAlert);
    }

    @TlsTest(description = "Clients MUST reject GREASE values when negotiated by the server. "
            + "In particular, the client MUST fail the connection "
            + "if a GREASE value appears in any of the following: "
            + "The \"cipher_suite\" value in a ServerHello")
    @ScopeLimitations(DerivationType.CIPHERSUITE)
    @ScopeExtensions(DerivationType.GREASE_CIPHERSUITE)
    @Handshake(SeverityLevel.MEDIUM)
    @Interoperability(SeverityLevel.HIGH)
    @Alert(SeverityLevel.MEDIUM)
    public void selectGreaseCipherSuite(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        CipherSuite greaseCipher = derivationContainer.getDerivation(GreaseCipherSuiteDerivation.class).getSelectedValue();

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsActions(new ReceiveAction(new AlertMessage()));

        ServerHelloMessage sh = workflowTrace.getFirstSendMessage(ServerHelloMessage.class);
        sh.setSelectedCipherSuite(Modifiable.explicit(greaseCipher.getByteValue()));

        runner.execute(workflowTrace, c).validateFinal(Validator::receivedFatalAlert);
    }

    @TlsTest(description = "Clients MUST reject GREASE values when negotiated by the server. "
            + "In particular, the client MUST fail the connection "
            + "if a GREASE value appears in any of the following: "
            + "Any ServerHello extension")
    @ScopeExtensions(DerivationType.GREASE_EXTENSION)
    @Handshake(SeverityLevel.MEDIUM)
    @Interoperability(SeverityLevel.HIGH)
    @Alert(SeverityLevel.MEDIUM)
    public void sendServerHelloGreaseExtension(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        ExtensionType greaseExtension = derivationContainer.getDerivation(GreaseExtensionDerivation.class).getSelectedValue();

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsActions(new ReceiveAction(new AlertMessage()));

        ServerHelloMessage sh = workflowTrace.getFirstSendMessage(ServerHelloMessage.class);
        sh.addExtension(new GreaseExtensionMessage(greaseExtension, 25));

        runner.execute(workflowTrace, c).validateFinal(Validator::receivedFatalAlert);
    }

    @TlsTest(description = "Clients MUST reject GREASE values when negotiated by the server. "
            + "In particular, the client MUST fail the connection "
            + "if a GREASE value appears in any of the following: "
            + "The \"namedcurve\" value in a ServerKeyExchange for an Ephemeral Elliptic Curve DiﬃeHellman (ECDHE) "
            + "cipher in TLS 1.2 [RFC5246] or earlier")
    @KeyExchange(supported = KeyExchangeType.ECDH, requiresServerKeyExchMsg = true)
    @ScopeLimitations(DerivationType.NAMED_GROUP)
    @ScopeExtensions(DerivationType.GREASE_NAMED_GROUP)
    @Handshake(SeverityLevel.MEDIUM)
    @Interoperability(SeverityLevel.HIGH)
    @Compliance(SeverityLevel.HIGH)
    @Alert(SeverityLevel.MEDIUM)
    public void selectGreaseNamedGroup(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsActions(new ReceiveAction(new AlertMessage()));

        NamedGroup greaseGroup = derivationContainer.getDerivation(GreaseNamedGroupDerivation.class).getSelectedValue();
        ECDHEServerKeyExchangeMessage skx = workflowTrace.getFirstSendMessage(ECDHEServerKeyExchangeMessage.class);
        skx.setNamedGroup(Modifiable.explicit(greaseGroup.getValue()));

        runner.execute(workflowTrace, c).validateFinal(Validator::receivedFatalAlert);
    }

    @TlsTest(description = "Clients MUST reject GREASE values when negotiated by the server. "
            + "In particular, the client MUST fail the connection "
            + "if a GREASE value appears in any of the following: "
            + "The signature algorithm in a ServerKeyExchange signature in TLS 1.2 or earlier")
    @KeyExchange(supported = KeyExchangeType.ALL12, requiresServerKeyExchMsg = true)
    @ScopeExtensions(DerivationType.GREASE_SIG_HASH)
    @Handshake(SeverityLevel.MEDIUM)
    @Interoperability(SeverityLevel.HIGH)
    @Compliance(SeverityLevel.HIGH)
    @Alert(SeverityLevel.MEDIUM)
    public void selectGreaseSignatureAlgorithm(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsActions(new ReceiveAction(new AlertMessage()));

        SignatureAndHashAlgorithm greaseSigHash = derivationContainer.getDerivation(GreaseSigHashDerivation.class).getSelectedValue();
        ServerKeyExchangeMessage skx = workflowTrace.getFirstSendMessage(ServerKeyExchangeMessage.class);
        skx.setSignatureAndHashAlgorithm(Modifiable.explicit(greaseSigHash.getByteValue()));

        runner.execute(workflowTrace, c).validateFinal(Validator::receivedFatalAlert);
    }
}
