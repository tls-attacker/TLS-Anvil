package de.rub.nds.tlstest.framework.anvil;

import static de.rub.nds.tlstest.framework.model.TlsParameterType.ADDITIONAL_PADDING_LENGTH;
import static de.rub.nds.tlstest.framework.model.TlsParameterType.ALERT;
import static de.rub.nds.tlstest.framework.model.TlsParameterType.APP_MSG_LENGHT;
import static de.rub.nds.tlstest.framework.model.TlsParameterType.AUTH_TAG_BITMASK;
import static de.rub.nds.tlstest.framework.model.TlsParameterType.CERTIFICATE;
import static de.rub.nds.tlstest.framework.model.TlsParameterType.CHOSEN_HANDSHAKE_MSG;
import static de.rub.nds.tlstest.framework.model.TlsParameterType.CIPHERTEXT_BITMASK;
import static de.rub.nds.tlstest.framework.model.TlsParameterType.CIPHER_SUITE;
import static de.rub.nds.tlstest.framework.model.TlsParameterType.COMPRESSION_METHOD;
import static de.rub.nds.tlstest.framework.model.TlsParameterType.EXTENSION;
import static de.rub.nds.tlstest.framework.model.TlsParameterType.FFDHE_SHARE_OUT_OF_BOUNDS;
import static de.rub.nds.tlstest.framework.model.TlsParameterType.GREASE_CIPHERSUITE;
import static de.rub.nds.tlstest.framework.model.TlsParameterType.GREASE_EXTENSION;
import static de.rub.nds.tlstest.framework.model.TlsParameterType.GREASE_NAMED_GROUP;
import static de.rub.nds.tlstest.framework.model.TlsParameterType.GREASE_PROTOCOL_VERSION;
import static de.rub.nds.tlstest.framework.model.TlsParameterType.GREASE_SIG_HASH;
import static de.rub.nds.tlstest.framework.model.TlsParameterType.HELLO_RETRY_COOKIE;
import static de.rub.nds.tlstest.framework.model.TlsParameterType.INCLUDE_ALPN_EXTENSION;
import static de.rub.nds.tlstest.framework.model.TlsParameterType.INCLUDE_CHANGE_CIPHER_SPEC;
import static de.rub.nds.tlstest.framework.model.TlsParameterType.INCLUDE_ENCRYPT_THEN_MAC_EXTENSION;
import static de.rub.nds.tlstest.framework.model.TlsParameterType.INCLUDE_EXTENDED_MASTER_SECRET_EXTENSION;
import static de.rub.nds.tlstest.framework.model.TlsParameterType.INCLUDE_GREASE_CIPHER_SUITES;
import static de.rub.nds.tlstest.framework.model.TlsParameterType.INCLUDE_GREASE_NAMED_GROUPS;
import static de.rub.nds.tlstest.framework.model.TlsParameterType.INCLUDE_GREASE_SIG_HASH_ALGORITHMS;
import static de.rub.nds.tlstest.framework.model.TlsParameterType.INCLUDE_HEARTBEAT_EXTENSION;
import static de.rub.nds.tlstest.framework.model.TlsParameterType.INCLUDE_PADDING_EXTENSION;
import static de.rub.nds.tlstest.framework.model.TlsParameterType.INCLUDE_PSK_EXCHANGE_MODES_EXTENSION;
import static de.rub.nds.tlstest.framework.model.TlsParameterType.INCLUDE_RENEGOTIATION_EXTENSION;
import static de.rub.nds.tlstest.framework.model.TlsParameterType.INCLUDE_SESSION_TICKET_EXTENSION;
import static de.rub.nds.tlstest.framework.model.TlsParameterType.INVALID_CCS_CONTENT;
import static de.rub.nds.tlstest.framework.model.TlsParameterType.MAC_BITMASK;
import static de.rub.nds.tlstest.framework.model.TlsParameterType.MAX_FRAGMENT_LENGTH;
import static de.rub.nds.tlstest.framework.model.TlsParameterType.MIRRORED_CIPHERSUITE;
import static de.rub.nds.tlstest.framework.model.TlsParameterType.NAMED_GROUP;
import static de.rub.nds.tlstest.framework.model.TlsParameterType.PADDING_BITMASK;
import static de.rub.nds.tlstest.framework.model.TlsParameterType.PRF_BITMASK;
import static de.rub.nds.tlstest.framework.model.TlsParameterType.PROTOCOL_MESSAGE_TYPE;
import static de.rub.nds.tlstest.framework.model.TlsParameterType.PROTOCOL_VERSION;
import static de.rub.nds.tlstest.framework.model.TlsParameterType.RECORD_LENGTH;
import static de.rub.nds.tlstest.framework.model.TlsParameterType.SIGNATURE_BITMASK;
import static de.rub.nds.tlstest.framework.model.TlsParameterType.SIG_HASH_ALGORIHTM;
import static de.rub.nds.tlstest.framework.model.TlsParameterType.TCP_FRAGMENTATION;

import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.model.parameter.ParameterFactory;
import de.rub.nds.anvilcore.model.parameter.ParameterIdentifier;
import de.rub.nds.anvilcore.model.parameter.ParameterScope;
import de.rub.nds.tlstest.framework.model.TlsParameterType;
import de.rub.nds.tlstest.framework.model.derivationParameter.AdditionalPaddingLengthDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.AlertDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.AppMsgLengthDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.AuthTagBitmaskDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.BitPositionDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.CertificateDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.ChosenHandshakeMessageDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.CipherSuiteDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.CipherTextBitmaskDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.CompressionMethodDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.ExtensionDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.GreaseCipherSuiteDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.GreaseExtensionDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.GreaseNamedGroupDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.GreaseProtocolVersionDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.GreaseSigHashDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.HelloRetryCookieDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.IncludeALPNExtensionDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.IncludeChangeCipherSpecDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.IncludeEncryptThenMacExtensionDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.IncludeExtendedMasterSecretExtensionDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.IncludeGreaseCipherSuitesDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.IncludeGreaseNamedGroupsDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.IncludeGreaseSigHashDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.IncludeHeartbeatExtensionDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.IncludePSKExchangeModesExtensionDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.IncludePaddingExtensionDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.IncludeRenegotiationExtensionDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.IncludeSessionTicketExtensionDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.InvalidCCSContentDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.MacBitmaskDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.MaxFragmentLengthDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.NamedGroupDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.PRFBitmaskDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.PaddingBitmaskDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.ProtocolMessageTypeDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.ProtocolVersionDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.RecordLengthDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.SigAndHashDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.SignatureBitmaskDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.TcpFragmentationDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.keyexchange.dhe.ShareOutOfBoundsDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.mirrored.MirroredCipherSuiteDerivation;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class TlsParameterFactory extends ParameterFactory {

    private static final Logger LOGGER = LogManager.getLogger();

    @Override
    public DerivationParameter getInstance(ParameterIdentifier parameterIdentifier) {
        // todo core - replace separate factory
        ParameterScope parameterScope = parameterIdentifier.getParameterScope();
        TlsParameterType type = (TlsParameterType) parameterIdentifier.getParameterType();
        if (parameterScope == ParameterScope.NO_SCOPE) {
            return createNoScopeInstance(type);
        } else if (parameterScope instanceof TlsParameterScope) {
            if (!parameterScope.getUniqueScopeIdentifier().contains("BITMASK")) {
                throw new IllegalArgumentException(
                        "Found ParameterIdentifier for TLS with scope set to "
                                + parameterScope
                                + ". Only bitmasks are supported.");
            } else {
                return new BitPositionDerivation(
                        new ParameterIdentifier(TlsParameterType.BIT_POSITION, parameterScope));
            }
        } else {
            throw new IllegalArgumentException(
                    "ParameterIdentifier "
                            + parameterIdentifier.toString()
                            + " was registered for TlsParameterFactory but the type is unknown.");
        }
    }

    private DerivationParameter createNoScopeInstance(TlsParameterType type)
            throws UnsupportedOperationException {
        switch (type) {
            case CIPHER_SUITE:
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
            case INCLUDE_SESSION_TICKET_EXTENSION:
                return new IncludeSessionTicketExtensionDerivation();
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
            case PROTOCOL_MESSAGE_TYPE:
                return new ProtocolMessageTypeDerivation();
            case FFDHE_SHARE_OUT_OF_BOUNDS:
                return new ShareOutOfBoundsDerivation();
            case MAX_FRAGMENT_LENGTH:
                return new MaxFragmentLengthDerivation();
            case HELLO_RETRY_COOKIE:
                return new HelloRetryCookieDerivation();
            default:
                LOGGER.error("Derivation Type {} not implemented", type);
                throw new UnsupportedOperationException("Derivation Type not implemented");
        }
    }

    @Override
    public ParameterScope resolveParameterScope(String scope) {
        return TlsParameterScope.resolveScope(scope);
    }
}
