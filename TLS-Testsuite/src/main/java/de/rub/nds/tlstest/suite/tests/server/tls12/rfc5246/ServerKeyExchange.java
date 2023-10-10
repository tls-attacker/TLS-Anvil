/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.server.tls12.rfc5246;

import static org.junit.Assert.assertTrue;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.DynamicValueConstraints;
import de.rub.nds.anvilcore.annotation.ServerTest;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.anvil.TlsTestCase;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
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
public class ServerKeyExchange extends Tls12Test {

    @AnvilTest
    @KeyExchange(supported = KeyExchangeType.ALL12, requiresServerKeyExchMsg = true)
    @DynamicValueConstraints(
            affectedIdentifiers = "CIPHER_SUITE",
            methods = "isSupportedCipherSuite")
    public void signatureIsValid(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = getPreparedConfig(argumentAccessor, runner);
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);

        runner.execute(workflowTrace, config)
                .validateFinal(
                        i -> {
                            Validator.executedAsPlanned(i);
                            assertTrue(
                                    "Server Key Exchange Message contained an invalid signature",
                                    signatureValid(i));
                        });
    }

    private Boolean signatureValid(TlsTestCase annotatedState) {
        WorkflowTrace executedTrace = annotatedState.getWorkflowTrace();
        ClientHelloMessage clientHello =
                (ClientHelloMessage)
                        WorkflowTraceUtil.getFirstSendMessage(
                                HandshakeMessageType.CLIENT_HELLO, executedTrace);
        ServerHelloMessage serverHello =
                (ServerHelloMessage)
                        WorkflowTraceUtil.getFirstReceivedMessage(
                                HandshakeMessageType.SERVER_HELLO, executedTrace);
        ServerKeyExchangeMessage serverKeyExchange =
                (ServerKeyExchangeMessage)
                        WorkflowTraceUtil.getFirstReceivedMessage(
                                HandshakeMessageType.SERVER_KEY_EXCHANGE, executedTrace);

        byte[] signedKeyExchangeParameters = getSignedDataFromKeyExchangeMessage(serverKeyExchange);
        byte[] completeSignedData =
                ArrayConverter.concatenate(
                        clientHello.getRandom().getValue(),
                        serverHello.getRandom().getValue(),
                        signedKeyExchangeParameters);

        byte[] givenSignature = serverKeyExchange.getSignature().getValue();
        SignatureAndHashAlgorithm selectedSignatureAndHashAlgo =
                SignatureAndHashAlgorithm.getSignatureAndHashAlgorithm(
                        serverKeyExchange.getSignatureAndHashAlgorithm().getValue());

        try {
            return SignatureValidation.validationSuccessful(
                    selectedSignatureAndHashAlgo,
                    annotatedState,
                    completeSignedData,
                    givenSignature);
        } catch (SignatureException
                | InvalidKeyException
                | InvalidKeySpecException
                | IOException
                | InvalidAlgorithmParameterException
                | NoSuchAlgorithmException ex) {
            throw new AssertionError("Was unable to process signature for validation: " + ex);
        }
    }

    private byte[] getSignedDataFromKeyExchangeMessage(ServerKeyExchangeMessage serverKeyExchange) {
        if (serverKeyExchange instanceof ECDHEServerKeyExchangeMessage) {
            ECDHEServerKeyExchangeMessage ecdheServerKeyExchange =
                    (ECDHEServerKeyExchangeMessage) serverKeyExchange;
            byte[] curveType = new byte[1];
            curveType[0] = ecdheServerKeyExchange.getGroupType().getValue();
            byte[] namedCurve = ecdheServerKeyExchange.getNamedGroup().getValue();
            byte[] publicKeyLength =
                    ecdheServerKeyExchange
                            .getPublicKeyLength()
                            .getByteArray(HandshakeByteLength.ECDHE_PARAM_LENGTH);
            byte[] publicKey = serverKeyExchange.getPublicKey().getValue();
            return ArrayConverter.concatenate(curveType, namedCurve, publicKeyLength, publicKey);
        } else if (serverKeyExchange instanceof DHEServerKeyExchangeMessage) {
            DHEServerKeyExchangeMessage dheServerKeyExchange =
                    (DHEServerKeyExchangeMessage) serverKeyExchange;
            return ArrayConverter.concatenate(
                    ArrayConverter.intToBytes(
                            dheServerKeyExchange.getModulusLength().getValue(),
                            HandshakeByteLength.DH_MODULUS_LENGTH),
                    dheServerKeyExchange.getModulus().getValue(),
                    ArrayConverter.intToBytes(
                            dheServerKeyExchange.getGeneratorLength().getValue(),
                            HandshakeByteLength.DH_GENERATOR_LENGTH),
                    dheServerKeyExchange.getGenerator().getValue(),
                    ArrayConverter.intToBytes(
                            dheServerKeyExchange.getPublicKeyLength().getValue(),
                            HandshakeByteLength.DH_PUBLICKEY_LENGTH),
                    dheServerKeyExchange.getPublicKey().getValue());

        } else {
            throw new AssertionError("Unsupported ServerKeyExchange type");
        }
    }

    public boolean isSupportedCipherSuite(CipherSuite cipherSuiteCandidate) {
        return cipherSuiteCandidate.isRealCipherSuite()
                && !cipherSuiteCandidate.isTLS13()
                && cipherSuiteCandidate.isEphemeral()
                && (AlgorithmResolver.getCertificateKeyType(cipherSuiteCandidate)
                                == CertificateKeyType.ECDSA
                        || AlgorithmResolver.getCertificateKeyType(cipherSuiteCandidate)
                                == CertificateKeyType.RSA
                        || AlgorithmResolver.getCertificateKeyType(cipherSuiteCandidate)
                                == CertificateKeyType.DSS);
    }
}
