/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.util;

import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.state.State;

public class SignatureValidation {
    public static Boolean validationSuccessful(
            SignatureAndHashAlgorithm selectedSignatureAndHashAlgo,
            State sessionState,
            byte[] completeSignedData,
            byte[] givenSignature) {
        // TODO: Implement TlsSignatureUtil.verifySignature in TLS attacker
        // For now, we assume every signature is valid
        return true;
    }
}
