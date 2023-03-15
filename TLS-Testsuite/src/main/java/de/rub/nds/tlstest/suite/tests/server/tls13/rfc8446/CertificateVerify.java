/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.server.tls13.rfc8446;

import static org.junit.Assert.assertTrue;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CertificateVerifyConstants;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.crypto.MessageDigestCollector;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.MessageAction;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.ServerTest;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.annotations.categories.ComplianceCategory;
import de.rub.nds.tlstest.framework.annotations.categories.CryptoCategory;
import de.rub.nds.tlstest.framework.annotations.categories.HandshakeCategory;
import de.rub.nds.tlstest.framework.annotations.categories.InteroperabilityCategory;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.AnnotatedState;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
import de.rub.nds.tlstest.suite.util.SignatureValidation;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

/** */
@Tag("signature")
@ServerTest
@RFC(number = 8446, section = "4.4.3.  Certificate Verify")
public class CertificateVerify extends Tls13Test {

    @TlsTest(
            description =
                    "Test if the Server sends Certificate Verify Messages with valid signatures")
    @InteroperabilityCategory(SeverityLevel.CRITICAL)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.CRITICAL)
    @CryptoCategory(SeverityLevel.CRITICAL)
    public void signatureIsValid(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);

        runner.execute(workflowTrace, config)
                .validateFinal(
                        i -> {
                            Validator.executedAsPlanned(i);
                            assertTrue(
                                    "Certificate Verify Message contained an invalid signature",
                                    signatureValid(i));
                        });
    }

    private boolean signatureValid(AnnotatedState annotatedState) {
        CertificateVerifyMessage certificateVerify =
                (CertificateVerifyMessage)
                        WorkflowTraceUtil.getFirstReceivedMessage(
                                HandshakeMessageType.CERTIFICATE_VERIFY,
                                annotatedState.getWorkflowTrace());
        SignatureAndHashAlgorithm selectedSignatureAndHashAlgo =
                SignatureAndHashAlgorithm.getSignatureAndHashAlgorithm(
                        certificateVerify.getSignatureHashAlgorithm().getValue());
        byte[] givenSignature = certificateVerify.getSignature().getValue();
        byte[] signedData = getCompleteSignedData(annotatedState);

        try {
            return SignatureValidation.validationSuccessful(
                    selectedSignatureAndHashAlgo, annotatedState, signedData, givenSignature);
        } catch (SignatureException
                | InvalidKeyException
                | InvalidKeySpecException
                | IOException
                | InvalidAlgorithmParameterException
                | NoSuchAlgorithmException ex) {
            throw new AssertionError("Was unable to process signature for validation: " + ex);
        }
    }

    private byte[] getCompleteSignedData(AnnotatedState annotatedState) {
        TlsContext postExecutionContext = annotatedState.getState().getTlsContext();
        WorkflowTrace executedTrace = annotatedState.getWorkflowTrace();

        byte[] signedTranscript = getSignedTranscript(executedTrace);
        MessageDigestCollector digestCollector = new MessageDigestCollector();
        digestCollector.setRawBytes(signedTranscript);

        return ArrayConverter.concatenate(
                ArrayConverter.hexStringToByteArray(
                        "2020202020202020202020202020202020202020202020202020"
                                + "2020202020202020202020202020202020202020202020202020202020202020202020202020"),
                CertificateVerifyConstants.SERVER_CERTIFICATE_VERIFY.getBytes(),
                new byte[] {(byte) 0x00},
                digestCollector.digest(
                        postExecutionContext.getSelectedProtocolVersion(),
                        postExecutionContext.getSelectedCipherSuite()));
    }

    private byte[] getSignedTranscript(WorkflowTrace executedTrace) {
        byte[] transcript = new byte[0];
        for (TlsAction workflowAction : executedTrace.getTlsActions()) {
            if (workflowAction instanceof MessageAction) {
                MessageAction messageAction = (MessageAction) workflowAction;
                for (ProtocolMessage message : messageAction.getMessages()) {
                    if (message instanceof CertificateVerifyMessage) {
                        return transcript;
                    } else {
                        if (message.isHandshakeMessage()) {
                            transcript =
                                    ArrayConverter.concatenate(
                                            transcript,
                                            message.getCompleteResultingMessage().getValue());
                        }
                    }
                }
            }
        }
        throw new AssertionError(
                "WorkflowTrace did not contain a Certificate Verify Message - cannot validate signature");
    }
}
