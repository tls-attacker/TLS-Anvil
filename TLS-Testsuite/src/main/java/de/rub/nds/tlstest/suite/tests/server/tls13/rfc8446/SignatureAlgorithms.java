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

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.ServerTest;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.AnnotatedStateContainer;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;

import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

@RFC(number = 8446, section = "4.2.3 Signature Algorithms")
@ServerTest
public class SignatureAlgorithms extends Tls13Test {

    @TlsTest(description = "If a server is authenticating via a certificate " +
            "and the client has not sent a \"signature_algorithms\" extension, " +
            "then the server MUST abort the handshake with " +
            "a \"missing_extension\" alert (see Section 9.2).")
    public void omitSignatureAlgorithmsExtension(WorkflowRunner runner) {
        runner.replaceSupportedCiphersuites = true;

        Config c = this.getConfig();
        c.setAddSignatureAndHashAlgorithmsExtension(false);

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                new SendAction(new ClientHelloMessage(c)),
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(workflowTrace, c).validateFinal(i -> {
            Validator.receivedFatalAlert(i);

            AlertMessage msg = i.getWorkflowTrace().getFirstReceivedMessage(AlertMessage.class);
            if (msg == null) return;
            Validator.testAlertDescription(i, AlertDescription.MISSING_EXTENSION, msg);
        });
    }

    @TlsTest(description = "Clients offering these values MUST list " +
            "them (legacy algorithms) as the lowest priority (listed after all other " +
            "algorithms in SignatureSchemeList).", securitySeverity = SeverityLevel.HIGH, interoperabilitySeverity = SeverityLevel.HIGH)
    public void offerLegacySignatureAlgorithms(WorkflowRunner runner) {
        runner.replaceSupportedCiphersuites = true;

        List<SignatureAndHashAlgorithm> algos = SignatureAndHashAlgorithm.getImplemented().stream()
                .filter(i -> !i.suitedForSigningTls13Messages())
                .collect(Collectors.toList());

        algos.addAll(SignatureAndHashAlgorithm.getImplemented().stream()
                .filter(SignatureAndHashAlgorithm::suitedForSigningTls13Messages)
                .collect(Collectors.toList())
        );

        Config c = this.getConfig();
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

    @TlsTest(description = "These values refer solely to signatures which appear in " +
            "certificates (see Section 4.4.2.2) and are not defined for use in " +
            "signed TLS handshake messages, although they MAY appear in \"signature_algorithms\" " +
            "and \"signature_algorithms_cert\" for backward " +
            "compatibility with TLS 1.2.", securitySeverity = SeverityLevel.HIGH)
    public void offerOnlyLegacySignatureAlgorithms(WorkflowRunner runner) {
        runner.replaceSupportedCiphersuites = true;

        List<SignatureAndHashAlgorithm> algos = SignatureAndHashAlgorithm.getImplemented().stream()
                .filter(i -> !i.suitedForSigningTls13Messages())
                .collect(Collectors.toList());

        AnnotatedStateContainer container = new AnnotatedStateContainer();
        for (SignatureAndHashAlgorithm i : algos) {
            Config c = this.getConfig();
            c.setDefaultClientSupportedSignatureAndHashAlgorithms(Collections.singletonList(i));

            WorkflowTrace workflowTrace = new WorkflowTrace();
            workflowTrace.addTlsActions(
                    new SendAction(new ClientHelloMessage(c)),
                    new ReceiveAction(new AlertMessage())
            );

            runner.setStateModifier(j -> {
                j.addAdditionalTestInfo(i.name());
                return null;
            });

            container.addAll(runner.prepare(workflowTrace, c));
        }

        runner.execute(container).validateFinal(Validator::receivedFatalAlert);
    }
}
