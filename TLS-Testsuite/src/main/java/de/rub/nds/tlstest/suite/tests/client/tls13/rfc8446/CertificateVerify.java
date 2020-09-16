/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.client.tls13.rfc8446;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.CertificateKeyType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.HashAlgorithm;
import de.rub.nds.tlsattacker.core.constants.SignatureAlgorithm;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.ClientTest;
import de.rub.nds.tlstest.framework.annotations.MethodCondition;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.AnnotatedStateContainer;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

@ClientTest
@RFC(number = 8446, section = "4.4.3. Certificate Verify")
public class CertificateVerify extends Tls13Test {

    public ConditionEvaluationResult supportsLegacyRSASAHAlgorithms() {
        List<SignatureAndHashAlgorithm> algos = context.getSiteReport().getSupportedSignatureAndHashAlgorithms();
        algos = algos.stream().filter(i -> i.getSignatureAlgorithm() == SignatureAlgorithm.RSA).collect(Collectors.toList());

        if (algos.size() > 0) {
            return ConditionEvaluationResult.enabled("");
        }
        return ConditionEvaluationResult.disabled("Client does not support legacy rsa signature and hash algorithms");
    }

    @TlsTest(description = "RSA signatures MUST use an RSASSA-PSS algorithm, " +
            "regardless of whether RSASSA-PKCS1-v1_5 algorithms " +
            "appear in \"signature_algorithms\". The SHA-1 algorithm " +
            "MUST NOT be used in any signatures of CertificateVerify messages.", securitySeverity = SeverityLevel.MEDIUM)
    @MethodCondition(method = "supportsLegacyRSASAHAlgorithms")
    public void selectLegacyRSASignatureAlgorithm(WorkflowRunner runner) {
        runner.replaceSelectedCiphersuite = true;

        Config c = this.getConfig();
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsActions(new ReceiveAction(new AlertMessage()));

        AnnotatedStateContainer container = new AnnotatedStateContainer();
        for (SignatureAndHashAlgorithm algo : context.getSiteReport().getSupportedSignatureAndHashAlgorithms()) {
            if (algo.getSignatureAlgorithm() == SignatureAlgorithm.RSA) {
                runner.setStateModifier(i -> {
                    WorkflowTrace trace = i.getWorkflowTrace();
                    i.addAdditionalTestInfo(algo.name());
                    trace.getFirstSendMessage(CertificateVerifyMessage.class)
                            .setSignatureHashAlgorithm(Modifiable.explicit(algo.getByteValue()));
                    return null;
                });

                container.addAll(runner.prepare(workflowTrace, c));
            }
        }

        runner.execute(container).validateFinal(Validator::receivedFatalAlert);
    }


    public ConditionEvaluationResult supportsLegacyECDSASAHAlgorithms() {
        if (context.getSiteReport().getSupportedSignatureAndHashAlgorithms().contains(SignatureAndHashAlgorithm.ECDSA_SHA1)) {
            return ConditionEvaluationResult.enabled("");
        }
        return ConditionEvaluationResult.disabled("Client does not support legacy rsa signature and hash algorithms");
    }

    @TlsTest(description = "RSA signatures MUST use an RSASSA-PSS algorithm, " +
            "regardless of whether RSASSA-PKCS1-v1_5 algorithms " +
            "appear in \"signature_algorithms\". The SHA-1 algorithm " +
            "MUST NOT be used in any signatures of CertificateVerify messages.", securitySeverity = SeverityLevel.MEDIUM)
    @MethodCondition(method = "supportsLegacyECDSASAHAlgorithms")
    public void selectLegacyECDSASignatureAlgorithm(WorkflowRunner runner) {
        runner.replaceSelectedCiphersuite = true;

        Config c = this.getConfig();
        c.setPreferedCertificateSignatureType(CertificateKeyType.ECDSA);
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsActions(new ReceiveAction(new AlertMessage()));

        runner.setStateModifier(i -> {
            WorkflowTrace trace = i.getWorkflowTrace();
            trace.getFirstSendMessage(CertificateVerifyMessage.class)
                    .setSignatureHashAlgorithm(Modifiable.explicit(SignatureAndHashAlgorithm.ECDSA_SHA1.getByteValue()));
            return null;
        });

        runner.execute(workflowTrace, c).validateFinal(Validator::receivedFatalAlert);
    }

    @TlsTest(description = "The receiver of a CertificateVerify message MUST verify " +
            "the signature field. If the verification fails, " +
            "the receiver MUST terminate the handshake with a \"decrypt_error\" alert.", securitySeverity = SeverityLevel.MEDIUM)
    public void invalidSignature(WorkflowRunner runner) {
        runner.replaceSelectedCiphersuite = true;

        List<CertificateKeyType> certificateKeyTypes = new ArrayList<CertificateKeyType>(){{
            add(CertificateKeyType.RSA);
        }};

        AnnotatedStateContainer container = new AnnotatedStateContainer();

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsActions(new ReceiveAction(new AlertMessage()));
        for (CertificateKeyType keyType : certificateKeyTypes) {
            List<SignatureAndHashAlgorithm> algorithms = context.getSiteReport().getSupportedSignatureAndHashAlgorithms().stream()
                    .filter(i -> i.getSignatureAlgorithm().toString().contains(keyType.toString()) &&
                            i.getHashAlgorithm() != HashAlgorithm.SHA1 &&
                            i.getSignatureAlgorithm() != SignatureAlgorithm.RSA &&
                            i.getSignatureAlgorithm() != SignatureAlgorithm.RSA_PSS_PSS)
                    .collect(Collectors.toList());
            if (algorithms.size() == 0) continue;

            for (SignatureAndHashAlgorithm sigHashAlg : algorithms) {
                Config c = this.getConfig();
                c.setPreferedCertificateSignatureType(keyType);
                c.setDefaultServerSupportedSignatureAndHashAlgorithms(sigHashAlg);

                runner.setStateModifier(i -> {
                    WorkflowTrace trace = i.getWorkflowTrace();
                    CertificateVerifyMessage msg = trace.getFirstSendMessage(CertificateVerifyMessage.class);
                    msg.setSignatureHashAlgorithm(Modifiable.explicit(sigHashAlg.getByteValue()));
                    msg.setSignature(Modifiable.xor(new byte[]{0x01}, 0));

                    i.addAdditionalTestInfo(keyType.toString());
                    i.addAdditionalTestInfo(sigHashAlg.toString());
                    return null;
                });

                container.addAll(runner.prepare(workflowTrace, c));
            }
        }

        runner.execute(container).validateFinal(i -> {
            Validator.receivedFatalAlert(i);

            AlertMessage msg = i.getWorkflowTrace().getFirstReceivedMessage(AlertMessage.class);
            if (msg == null) return;
            Validator.testAlertDescription(i, AlertDescription.DECRYPT_ERROR, msg);
        });
    }


    @TlsTest(description = "Servers MUST send this message when authenticating via a certificate.",
        securitySeverity = SeverityLevel.CRITICAL)
    public void omitCertificateVerify(WorkflowRunner runner) {
        runner.replaceSelectedCiphersuite = true;

        WorkflowTrace trace = runner.generateWorkflowTraceUntilSendingMessage(WorkflowTraceType.HELLO, HandshakeMessageType.CERTIFICATE_VERIFY);
        trace.addTlsActions(
                new SendAction(new FinishedMessage()),
                new ReceiveAction(new AlertMessage())
        );

        runner.execute(trace, this.getConfig()).validateFinal(Validator::receivedFatalAlert);
    }

    @TlsTest(description = "Servers MUST send this message when authenticating via a certificate.",
            securitySeverity = SeverityLevel.CRITICAL)
    public void emptySignature(WorkflowRunner runner) {
        runner.replaceSelectedCiphersuite = true;

        WorkflowTrace trace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        trace.addTlsActions(
                new ReceiveAction(new AlertMessage())
        );

        runner.setStateModifier(i -> {
            i.getWorkflowTrace().getFirstSendMessage(CertificateVerifyMessage.class)
                    .setSignature(Modifiable.explicit(new byte[]{}));
            return null;
        });

        runner.execute(trace, this.getConfig()).validateFinal(Validator::receivedFatalAlert);
    }

    @TlsTest(description = "Servers MUST send this message when authenticating via a certificate.",
            securitySeverity = SeverityLevel.CRITICAL)
    public void emptySigAlgorithm(WorkflowRunner runner) {
        runner.replaceSelectedCiphersuite = true;

        WorkflowTrace trace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        trace.addTlsActions(
                new ReceiveAction(new AlertMessage())
        );

        runner.setStateModifier(i -> {
            i.getWorkflowTrace().getFirstSendMessage(CertificateVerifyMessage.class)
                    .setSignatureHashAlgorithm(Modifiable.explicit(new byte[]{}));
            return null;
        });

        runner.execute(trace, this.getConfig()).validateFinal(Validator::receivedFatalAlert);
    }

    @TlsTest(description = "Servers MUST send this message when authenticating via a certificate.",
            securitySeverity = SeverityLevel.CRITICAL)
    public void emptyBoth(WorkflowRunner runner) {
        runner.replaceSelectedCiphersuite = true;

        WorkflowTrace trace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        trace.addTlsActions(
                new ReceiveAction(new AlertMessage())
        );

        runner.setStateModifier(i -> {
            i.getWorkflowTrace().getFirstSendMessage(CertificateVerifyMessage.class)
                    .setSignatureHashAlgorithm(Modifiable.explicit(new byte[]{}));
            i.getWorkflowTrace().getFirstSendMessage(CertificateVerifyMessage.class)
                    .setSignature(Modifiable.explicit(new byte[]{}));
            return null;
        });

        runner.execute(trace, this.getConfig()).validateFinal(Validator::receivedFatalAlert);
    }


}
