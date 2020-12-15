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
import de.rub.nds.tlstest.framework.model.derivationParameter.mirrored.MirroredCipherSuiteDerivation;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

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
            case PROTOCOL_VERSION:
                return new ProtocolVersionDerivation();
            case SIG_HASH_ALGORIHTM:
                return new SigAndHashDerivation();
            case EXTENSION:
                return new ExtensionDerivation();
            case CHOSEN_HANDSHAKE_MSG:
                return new ChosenHandshakeMessageDerivation();
            case MIRRORED_CIPHERSUITE:
                return new MirroredCipherSuiteDerivation();
            case CERTIFICATE:
                return new CertificateDerivation();
            case SIGNATURE_BITMASK:
                return new SignatureBitmaskDerivation();
            case INCLUDE_ALPN_EXTENSION:
                return new IncludeALPNExtensionDerivation();
            case INCLUDE_CHANGE_CIPHER_SPEC:
                return new IncludeChangeCipherSpecDerivation();
            case INCLUDE_ENCRYPT_THEN_MAC_EXTENSION:
                return new IncludeEncryptThenMacExtensionDerivation();
            case INCLUDE_EXTENDED_MASTER_SECRET_EXTENSION:
                return new IncludeExtendedMasterSecretExtensionDerivation();
            case INCLUDE_HEARTBEAT_EXTENSION:
                return new IncludeHeartbeatExtensionDerivation();
            case INCLUDE_PADDING_EXTENSION:
                return new IncludePaddingExtensionDerivation();
            case INCLUDE_PSK_EXCHANGE_MODES_EXTENSION:
                return new IncludePSKExchangeModesExtensionDerivation();
            case INCLUDE_RENEGOTIATION_EXTENSION:
                return new IncludeRenegotiationExtensionDerivation();
            case INCLUDE_GREASE_CIPHER_SUITES:
                return new IncludeGreaseCipherSuitesDerivation();
            case INCLUDE_GREASE_NAMED_GROUPS:
                return new IncludeGreaseNamedGroupsDerivation();
            case INCLUDE_GREASE_SIG_HASH_ALGORITHMS:
                return new IncludeGreaseSigHashDerivation();
            case ADDITIONAL_PADDING_LENGTH:
                return new AdditionalPaddingLengthDerivation();
            case COMPRESSION_METHOD:
                return new CompressionMethodDerivation();
            default:
                throw new UnsupportedOperationException("Derivation Type not implemented");
        }
    }
}
