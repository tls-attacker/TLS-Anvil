package de.rub.nds.tlstest.suite.tests.server.tls13.rfc8446;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CertificateVerifyConstants;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.crypto.MessageDigestCollector;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.MessageAction;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.annotations.ServerTest;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.annotations.categories.Alert;
import de.rub.nds.tlstest.framework.annotations.categories.Compliance;
import de.rub.nds.tlstest.framework.annotations.categories.Crypto;
import de.rub.nds.tlstest.framework.annotations.categories.DeprecatedFeature;
import de.rub.nds.tlstest.framework.annotations.categories.Handshake;
import de.rub.nds.tlstest.framework.annotations.categories.Interoperability;
import de.rub.nds.tlstest.framework.annotations.categories.MessageStructure;
import de.rub.nds.tlstest.framework.annotations.categories.Security;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.AnnotatedState;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import static org.junit.Assert.assertTrue;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

/**
 *
 */
@Tag("signature")
@ServerTest
public class CertificateVerify extends Tls13Test {

    @TlsTest(description = "Test if the Server sends Certificate Verify Messages with valid signatures")
    @Interoperability(SeverityLevel.CRITICAL)
    @Handshake(SeverityLevel.MEDIUM)
    @Compliance(SeverityLevel.CRITICAL)
    @Crypto(SeverityLevel.CRITICAL)
    @Security(SeverityLevel.CRITICAL)
    /* Categories MM: I think we should remove Security here*/
    public void signatureIsValid(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);

        runner.execute(workflowTrace, config).validateFinal(i -> {

            Validator.executedAsPlanned(i);
            assertTrue("Certificate Verify Message contained an invalid signature", signatureValid(i));
        });
    }

    private boolean signatureValid(AnnotatedState annotatedState) {
        CertificateVerifyMessage certificateVerify = (CertificateVerifyMessage) WorkflowTraceUtil.getFirstReceivedMessage(HandshakeMessageType.CERTIFICATE_VERIFY, annotatedState.getWorkflowTrace());
        SignatureAndHashAlgorithm selectedSignatureAndHashAlgo = SignatureAndHashAlgorithm.getSignatureAndHashAlgorithm(certificateVerify.getSignatureHashAlgorithm().getValue());
        byte[] givenSignature = certificateVerify.getSignature().getValue();
        byte[] signedData = getCompleteSignedData(annotatedState);
        Signature signatureInstance;

        try {
            signatureInstance = Signature.getInstance(selectedSignatureAndHashAlgo.getJavaName());
            selectedSignatureAndHashAlgo.setupSignature(signatureInstance);

            X509EncodedKeySpec rsaKeySpec = new X509EncodedKeySpec(annotatedState.getState().getTlsContext().getServerCertificate().getCertificateAt(0).getSubjectPublicKeyInfo().getEncoded());
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey rsaPublicKey = keyFactory.generatePublic(rsaKeySpec);

            signatureInstance.initVerify(rsaPublicKey);
            signatureInstance.update(signedData);
            return signatureInstance.verify(givenSignature);
        } catch (SignatureException | InvalidKeyException | InvalidKeySpecException | IOException | InvalidAlgorithmParameterException | NoSuchAlgorithmException ex) {
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
                        ArrayConverter.hexStringToByteArray("2020202020202020202020202020202020202020202020202020"
                                + "2020202020202020202020202020202020202020202020202020202020202020202020202020"),
                        CertificateVerifyConstants.SERVER_CERTIFICATE_VERIFY.getBytes(),
                        new byte[]{(byte) 0x00},
                        digestCollector.digest(postExecutionContext.getSelectedProtocolVersion(), postExecutionContext.getSelectedCipherSuite()));
        
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
                            transcript = ArrayConverter.concatenate(transcript, message.getCompleteResultingMessage().getValue());
                        }
                    }
                }
            }
        }
        throw new AssertionError("WorkflowTrace did not contain a Certificate Verify Message - cannot validate signature");
    }
}
