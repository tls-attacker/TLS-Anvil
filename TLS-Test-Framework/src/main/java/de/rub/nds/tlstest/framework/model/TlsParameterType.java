/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.model;

import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.model.parameter.ParameterIdentifier;
import de.rub.nds.anvilcore.model.parameter.ParameterScope;
import de.rub.nds.anvilcore.model.parameter.ParameterType;
import de.rub.nds.tlstest.framework.anvil.BitPositionParameterScope;
import de.rub.nds.tlstest.framework.model.derivationParameter.*;
import de.rub.nds.tlstest.framework.model.derivationParameter.keyexchange.dhe.ShareOutOfBoundsDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.mirrored.MirroredCipherSuiteDerivation;
import java.lang.reflect.InvocationTargetException;

/** Represents the properties affected by the test derivation models. */
public enum TlsParameterType implements ParameterType {
    CIPHER_SUITE(CipherSuiteDerivation.class),
    NAMED_GROUP(NamedGroupDerivation.class),
    MAC_BITMASK(MacBitmaskDerivation.class),
    ALERT(AlertDerivation.class),
    RECORD_LENGTH(RecordLengthDerivation.class),
    TCP_FRAGMENTATION(TcpFragmentationDerivation.class),
    CIPHERTEXT_BITMASK(CipherTextBitmaskDerivation.class),
    AUTH_TAG_BITMASK(AuthTagBitmaskDerivation.class),
    APP_MSG_LENGHT(AppMsgLengthDerivation.class),
    PADDING_BITMASK(PaddingBitmaskDerivation.class),
    INVALID_CCS_CONTENT(InvalidCCSContentDerivation.class),
    PRF_BITMASK(PRFBitmaskDerivation.class),
    GREASE_CIPHERSUITE(GreaseCipherSuiteDerivation.class),
    GREASE_PROTOCOL_VERSION(GreaseProtocolVersionDerivation.class),
    GREASE_EXTENSION(GreaseExtensionDerivation.class),
    GREASE_NAMED_GROUP(GreaseNamedGroupDerivation.class),
    GREASE_SIG_HASH(GreaseSigHashDerivation.class),
    PROTOCOL_VERSION(ProtocolVersionDerivation.class),
    SIG_HASH_ALGORIHTM(SigAndHashDerivation.class),
    EXTENSION(ExtensionDerivation.class),
    CHOSEN_HANDSHAKE_MSG(ChosenHandshakeMessageDerivation.class),
    MIRRORED_CIPHERSUITE(MirroredCipherSuiteDerivation.class),
    CERTIFICATE(CertificateDerivation.class),
    SIGNATURE_BITMASK(SigAndHashDerivation.class),
    BIT_POSITION(BitPositionDerivation.class),
    INCLUDE_RENEGOTIATION_EXTENSION(IncludeRenegotiationExtensionDerivation.class),
    INCLUDE_EXTENDED_MASTER_SECRET_EXTENSION(IncludeExtendedMasterSecretExtensionDerivation.class),
    INCLUDE_PADDING_EXTENSION(IncludePaddingExtensionDerivation.class),
    INCLUDE_ENCRYPT_THEN_MAC_EXTENSION(IncludeEncryptThenMacExtensionDerivation.class),
    INCLUDE_ALPN_EXTENSION(IncludeALPNExtensionDerivation.class),
    INCLUDE_HEARTBEAT_EXTENSION(IncludeHeartbeatExtensionDerivation.class),
    INCLUDE_CHANGE_CIPHER_SPEC(IncludeChangeCipherSpecDerivation.class),
    INCLUDE_PSK_EXCHANGE_MODES_EXTENSION(IncludePSKExchangeModesExtensionDerivation.class),
    INCLUDE_SESSION_TICKET_EXTENSION(IncludeSessionTicketExtensionDerivation.class),
    INCLUDE_GREASE_CIPHER_SUITES(IncludeGreaseCipherSuitesDerivation.class),
    INCLUDE_GREASE_SIG_HASH_ALGORITHMS(IncludeGreaseSigHashDerivation.class),
    INCLUDE_GREASE_NAMED_GROUPS(IncludeGreaseNamedGroupsDerivation.class),
    ADDITIONAL_PADDING_LENGTH(AdditionalPaddingLengthDerivation.class),
    COMPRESSION_METHOD(CompressionMethodDerivation.class),
    PROTOCOL_MESSAGE_TYPE(ProtocolMessageTypeDerivation.class),
    FFDHE_SHARE_OUT_OF_BOUNDS(ShareOutOfBoundsDerivation.class),
    MAX_FRAGMENT_LENGTH(MaxFragmentLengthDerivation.class),
    HELLO_RETRY_COOKIE(HelloRetryCookieDerivation.class),
    COOKIE_EXCHANGE(CookieExchangeDerivation.class),
    DTLS_COOKIE_BITMASK(DtlsCookieBitmaskDerivation.class);

    TlsParameterType(Class<? extends DerivationParameter> derivationClass) {
        this.derivationClass = derivationClass;
    }

    private Class<? extends DerivationParameter> derivationClass;

    public boolean isBitmaskDerivation() {
        return this.name().contains("BITMASK");
    }

    @Override
    public DerivationParameter getInstance(ParameterScope parameterScope) {
        if (parameterScope == ParameterScope.NO_SCOPE) {
            try {
                return derivationClass.getDeclaredConstructor().newInstance();
            } catch (InstantiationException
                    | IllegalAccessException
                    | InvocationTargetException
                    | NoSuchMethodException e) {
                throw new RuntimeException(e);
            }
        } else if (parameterScope instanceof BitPositionParameterScope) {
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
                    "ParameterScope " + parameterScope.toString() + " is not known.");
        }
    }
}
