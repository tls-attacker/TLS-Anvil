/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.util;

import de.rub.nds.tlsattacker.core.constants.CertificateKeyType;
import de.rub.nds.tlsattacker.core.constants.SignatureAlgorithm;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlstest.framework.anvil.TlsTestState;
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

public class SignatureValidation {
    public static Boolean validationSuccessful(
            SignatureAndHashAlgorithm selectedSignatureAndHashAlgo,
            TlsTestState annotatedState,
            byte[] completeSignedData,
            byte[] givenSignature)
            throws SignatureException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
                    InvalidKeyException, IOException, InvalidKeySpecException {
        State sessionState = annotatedState.getState();
        Signature signatureInstance =
                Signature.getInstance(selectedSignatureAndHashAlgo.getJavaName());
        selectedSignatureAndHashAlgo.setupSignature(signatureInstance);
        X509EncodedKeySpec keySpec =
                new X509EncodedKeySpec(
                        sessionState
                                .getTlsContext()
                                .getServerCertificate()
                                .getCertificateAt(0)
                                .getSubjectPublicKeyInfo()
                                .getEncoded());

        KeyFactory keyFactory;
        PublicKey publicKey;
        if (selectedSignatureAndHashAlgo.getSignatureAlgorithm() == SignatureAlgorithm.ECDSA) {
            keyFactory = KeyFactory.getInstance("EC");
            publicKey = keyFactory.generatePublic(keySpec);
        } else if (selectedSignatureAndHashAlgo
                        .getSignatureAlgorithm()
                        .getRequiredCertificateKeyType()
                == CertificateKeyType.RSA) {
            keyFactory = KeyFactory.getInstance("RSA");
            publicKey = keyFactory.generatePublic(keySpec);
        } else if (selectedSignatureAndHashAlgo.getSignatureAlgorithm() == SignatureAlgorithm.DSA) {
            keyFactory = KeyFactory.getInstance("DSA");
            publicKey = keyFactory.generatePublic(keySpec);
        } else {
            throw new UnsupportedOperationException(
                    "Signature verification is not implemented for algorithm "
                            + selectedSignatureAndHashAlgo);
        }

        signatureInstance.initVerify(publicKey);
        signatureInstance.update(completeSignedData);
        return signatureInstance.verify(givenSignature);
    }
}
