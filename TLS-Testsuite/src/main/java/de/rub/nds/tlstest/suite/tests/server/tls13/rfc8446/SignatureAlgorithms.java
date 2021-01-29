/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.server.tls13.rfc8446;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SignatureAndHashAlgorithmsExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.ExplicitValues;
import de.rub.nds.tlstest.framework.annotations.ManualConfig;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.ScopeExtensions;
import de.rub.nds.tlstest.framework.annotations.ServerTest;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.annotations.categories.AlertCategory;
import de.rub.nds.tlstest.framework.annotations.categories.ComplianceCategory;
import de.rub.nds.tlstest.framework.annotations.categories.CryptoCategory;
import de.rub.nds.tlstest.framework.annotations.categories.DeprecatedFeatureCategory;
import de.rub.nds.tlstest.framework.annotations.categories.HandshakeCategory;
import de.rub.nds.tlstest.framework.annotations.categories.InteroperabilityCategory;
import de.rub.nds.tlstest.framework.annotations.categories.MessageStructureCategory;
import de.rub.nds.tlstest.framework.annotations.categories.SecurityCategory;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.DerivationScope;
import de.rub.nds.tlstest.framework.model.DerivationType;
import de.rub.nds.tlstest.framework.model.derivationParameter.DerivationParameter;
import de.rub.nds.tlstest.framework.model.derivationParameter.SigAndHashDerivation;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;

import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@RFC(number = 8446, section = "4.2.3 Signature Algorithms")
@ServerTest
public class SignatureAlgorithms extends Tls13Test {

    @TlsTest(description = "If a server is authenticating via a certificate "
            + "and the client has not sent a \"signature_algorithms\" extension, "
            + "then the server MUST abort the handshake with "
            + "a \"missing_extension\" alert (see Section 9.2).")
    @InteroperabilityCategory(SeverityLevel.HIGH)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.MEDIUM)
    public void omitSignatureAlgorithmsExtension(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        c.setAddSignatureAndHashAlgorithmsExtension(false);

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                new SendAction(new ClientHelloMessage(c)),
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(workflowTrace, c).validateFinal(i -> {
            Validator.receivedFatalAlert(i);

            AlertMessage msg = i.getWorkflowTrace().getFirstReceivedMessage(AlertMessage.class);
            if (msg == null) {
                return;
            }
            Validator.testAlertDescription(i, AlertDescription.MISSING_EXTENSION, msg);
        });
    }

    public List<DerivationParameter> getLegacySigHashAlgoritms(DerivationScope scope) {
        List<DerivationParameter> parameterValues = new LinkedList<>();
        List<SignatureAndHashAlgorithm> algos = SignatureAndHashAlgorithm.getImplemented().stream()
                .filter(i -> !i.suitedForSigningTls13Messages())
                .collect(Collectors.toList());
        algos.forEach(i -> parameterValues.add(new SigAndHashDerivation(i)));
        return parameterValues;
    }

    @TlsTest(description = "Clients offering these values MUST list "
            + "them (legacy algorithms) as the lowest priority (listed after all other "
            + "algorithms in SignatureSchemeList).")
    @ScopeExtensions(DerivationType.SIG_HASH_ALGORIHTM)
    @ManualConfig(DerivationType.SIG_HASH_ALGORIHTM)
    @ExplicitValues(affectedTypes = DerivationType.SIG_HASH_ALGORIHTM, methods = "getLegacySigHashAlgoritms")
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    @SecurityCategory(SeverityLevel.MEDIUM)
    public void offerLegacySignatureAlgorithms(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        SignatureAndHashAlgorithm selectedSigHash = derivationContainer.getDerivation(SigAndHashDerivation.class).getSelectedValue();

        List<SignatureAndHashAlgorithm> algos = SignatureAndHashAlgorithm.getImplemented().stream()
                .filter(SignatureAndHashAlgorithm::suitedForSigningTls13Messages)
                .collect(Collectors.toList());
        algos.add(0, selectedSigHash);

        c.setDefaultClientSupportedSignatureAndHashAlgorithms(algos);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);

        runner.execute(workflowTrace, c).validateFinal(i -> {
            Validator.executedAsPlanned(i);

            CertificateVerifyMessage certVerifyMsg = i.getWorkflowTrace().getFirstReceivedMessage(CertificateVerifyMessage.class);
            assertNotNull(certVerifyMsg);
            SignatureAndHashAlgorithm sigHashAlg = SignatureAndHashAlgorithm.getSignatureAndHashAlgorithm(certVerifyMsg.getSignatureHashAlgorithm().getValue());
            assertTrue("Invalid SignatureAndHashAlgorithm negotiated", sigHashAlg.suitedForSigningTls13Messages());
        });
    }

    @TlsTest(description = "These values refer solely to signatures which appear in "
            + "certificates (see Section 4.4.2.2) and are not defined for use in "
            + "signed TLS handshake messages, although they MAY appear in \"signature_algorithms\" "
            + "and \"signature_algorithms_cert\" for backward "
            + "compatibility with TLS 1.2.")
    @ScopeExtensions(DerivationType.SIG_HASH_ALGORIHTM)
    @ExplicitValues(affectedTypes = DerivationType.SIG_HASH_ALGORIHTM, methods = "getLegacySigHashAlgoritms")
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    @SecurityCategory(SeverityLevel.MEDIUM)
    public void offerOnlyLegacySignatureAlgorithms(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                new SendAction(new ClientHelloMessage(c)),
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(workflowTrace, c).validateFinal(Validator::receivedFatalAlert);
    }

    @TlsTest(description = "Perform a Handshake where the Signature and Hash Algorithms Extension contains an additional, undefined algorithm")
    @InteroperabilityCategory(SeverityLevel.HIGH)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    public void includeUnknownSignatureAndHashAlgorithm(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        c.setAddSignatureAndHashAlgorithmsExtension(true);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        ClientHelloMessage clientHello = (ClientHelloMessage) WorkflowTraceUtil.getFirstSendMessage(HandshakeMessageType.CLIENT_HELLO, workflowTrace);
        SignatureAndHashAlgorithmsExtensionMessage algorithmsExtension = clientHello.getExtension(SignatureAndHashAlgorithmsExtensionMessage.class);
        algorithmsExtension.setSignatureAndHashAlgorithms(Modifiable.insert(new byte[]{(byte) 0xfe, 0x44}, 0));

        runner.execute(workflowTrace, c).validateFinal(Validator::executedAsPlanned);
    }
}
