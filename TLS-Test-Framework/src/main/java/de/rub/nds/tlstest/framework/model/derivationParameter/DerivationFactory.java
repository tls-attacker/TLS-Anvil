/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.model.derivationParameter;

import de.rub.nds.tlstest.framework.model.DerivationType;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author marcel
 */
public class DerivationFactory {
    
    private static final Logger LOGGER = LogManager.getLogger();
    
    public static DerivationParameter getInstance(DerivationType type) {
        switch(type) {
            case CIPHERSUITE:
                return new CipherSuiteDerivation();
            case MAC_BITMASK:
                return new MacBitmaskDerivation();
            case ALERT:
                return new AlertDerivation();
            case NAMED_GROUP:
                return new NamedGroupDerivation();
            case RECORD_LENGTH:
                return new RecordLengthDerivation();
            case TCP_FRAGMENTATION:
                return new TcpFragmentationDerivation();
            case CIPHERTEXT_BITMASK:
                return new CipherTextBitmaskDerivation();
            case AUTH_TAG_BITMASK:
                return new AuthTagBitmaskDerivation();
            case APP_MSG_LENGHT:
                return new AppMsgLengthDerivation();
            case BIT_POSITION:
                return new BitPositionDerivation();
            case PADDING_BITMASK:
                return new PaddingBitmaskDerivation();
            case INVALID_CCS_CONTENT:
                return new InvalidCCSContentDerivation();
            case PRF_BITMASK:
                return new PRFBitmaskDerivation();
            case GREASE_CIPHERSUITE:
                return new GreaseCipherSuiteDerivation();
            case GREASE_EXTENSION:
                return new GreaseExtensionDerivation();
            case GREASE_NAMED_GROUP:
                return new GreaseNamedGroupDerivation();
            case GREASE_PROTOCOL_VERSION:
                return new GreaseProtocolVersionDerivation();
            case GREASE_SIG_HASH:
                return new GreaseSigHashDerivation();
            default:
                throw new UnsupportedOperationException("Derivation Type not implemented");
        }
    }
}
