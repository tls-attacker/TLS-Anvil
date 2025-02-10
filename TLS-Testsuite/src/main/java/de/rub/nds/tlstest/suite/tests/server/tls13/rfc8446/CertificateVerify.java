/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.server.tls13.rfc8446;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.ServerTest;
import de.rub.nds.anvilcore.teststate.AnvilTestCase;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CertificateVerifyConstants;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.crypto.MessageDigestCollector;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceResultUtil;
import de.rub.nds.tlsattacker.core.workflow.action.*;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
import de.rub.nds.tlstest.suite.util.SignatureValidation;
import java.util.List;
import org.junit.jupiter.api.Tag;

/** */
@Tag("signature")
@ServerTest
public class CertificateVerify extends Tls13Test {

    @AnvilTest(id = "8446-qfG8mSV78A")
    public void signatureIsValid(AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);

        State state = runner.execute(workflowTrace, config);

        Validator.executedAsPlanned(state, testCase);
        assertTrue(
                signatureValid(state), "Certificate Verify Message contained an invalid signature");
    }

    private boolean signatureValid(State state) {
        CertificateVerifyMessage certificateVerify =
                (CertificateVerifyMessage)
                        WorkflowTraceResultUtil.getFirstReceivedMessage(
                                state.getWorkflowTrace(), HandshakeMessageType.CERTIFICATE_VERIFY);
        SignatureAndHashAlgorithm selectedSignatureAndHashAlgo =
                SignatureAndHashAlgorithm.getSignatureAndHashAlgorithm(
                        certificateVerify.getSignatureHashAlgorithm().getValue());
        byte[] givenSignature = certificateVerify.getSignature().getValue();
        byte[] signedData = getCompleteSignedData(state);

        return SignatureValidation.validationSuccessful(
                selectedSignatureAndHashAlgo, state, signedData, givenSignature);
    }

    private byte[] getCompleteSignedData(State state) {
        TlsContext postExecutionContext = state.getTlsContext();
        WorkflowTrace executedTrace = state.getWorkflowTrace();

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
                List<ProtocolMessage> messages =
                        messageAction.isReceivingAction()
                                ? ((ReceivingAction) messageAction).getReceivedMessages()
                                : ((SendingAction) messageAction).getSentMessages();
                for (ProtocolMessage message : messages) {
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
