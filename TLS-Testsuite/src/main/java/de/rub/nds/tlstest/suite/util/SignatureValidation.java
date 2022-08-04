/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * Copyright 2022 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.util;

import de.rub.nds.tlsattacker.core.constants.SignatureAlgorithm;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlstest.framework.execution.AnnotatedState;
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
    public static Boolean validationSuccessful(SignatureAndHashAlgorithm selectedSignatureAndHashAlgo, AnnotatedState annotatedState, byte[] completeSignedData, byte[] givenSignature) throws SignatureException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, InvalidKeyException, IOException, InvalidKeySpecException {
        State sessionState = annotatedState.getState();
        Signature signatureInstance = Signature.getInstance(selectedSignatureAndHashAlgo.getJavaName());
        selectedSignatureAndHashAlgo.setupSignature(signatureInstance);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(sessionState.getTlsContext().getServerCertificate().getCertificateAt(0).getSubjectPublicKeyInfo().getEncoded());
        
        KeyFactory keyFactory;
        PublicKey publicKey;
        if(selectedSignatureAndHashAlgo.getSignatureAlgorithm() == SignatureAlgorithm.ECDSA) {
            keyFactory = KeyFactory.getInstance("EC");
            publicKey = keyFactory.generatePublic(keySpec);
        } else if(selectedSignatureAndHashAlgo.getSignatureAlgorithm() == SignatureAlgorithm.RSA) {
            keyFactory = KeyFactory.getInstance("RSA");
            publicKey = keyFactory.generatePublic(keySpec);
        } else {
            keyFactory = KeyFactory.getInstance("DSA");
            publicKey = keyFactory.generatePublic(keySpec);
        }
        
        signatureInstance.initVerify(publicKey);
        signatureInstance.update(completeSignedData);
        return signatureInstance.verify(givenSignature);
    }
}
