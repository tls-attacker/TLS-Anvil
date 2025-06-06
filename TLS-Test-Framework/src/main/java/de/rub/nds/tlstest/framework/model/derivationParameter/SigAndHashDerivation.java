/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.model.derivationParameter;

import de.rub.nds.anvilcore.constants.TestEndpointType;
import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.constraint.ConditionalConstraint;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.model.parameter.ParameterIdentifier;
import de.rub.nds.protocol.constants.HashAlgorithm;
import de.rub.nds.protocol.constants.SignatureAlgorithm;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlstest.framework.ClientFeatureExtractionResult;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.anvil.TlsDerivationParameter;
import de.rub.nds.tlstest.framework.anvil.TlsParameterIdentifierProvider;
import de.rub.nds.tlstest.framework.model.TlsParameterType;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.constants.X509PublicKeyType;
import de.rwth.swc.coffee4j.model.constraints.ConstraintBuilder;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

/** */
public class SigAndHashDerivation extends TlsDerivationParameter<SignatureAndHashAlgorithm> {

    public SigAndHashDerivation() {
        super(TlsParameterType.SIG_HASH_ALGORIHTM, SignatureAndHashAlgorithm.class);
    }

    public SigAndHashDerivation(SignatureAndHashAlgorithm selectedValue) {
        this();
        setSelectedValue(selectedValue);
    }

    @Override
    public List<DerivationParameter<Config, SignatureAndHashAlgorithm>> getParameterValues(
            DerivationScope derivationScope) {
        List<DerivationParameter<Config, SignatureAndHashAlgorithm>> parameterValues =
                new LinkedList<>();
        if (context.getConfig().getTestEndpointMode() == TestEndpointType.CLIENT) {
            ClientFeatureExtractionResult extractionResult =
                    (ClientFeatureExtractionResult) context.getFeatureExtractionResult();
            if (extractionResult.getAdvertisedSignatureAndHashAlgorithms() == null
                    || extractionResult.getAdvertisedSignatureAndHashAlgorithms().isEmpty()) {
                parameterValues = getClientTestDefaultAlgorithms();
            } else {
                parameterValues = getClientTestAlgorithms(extractionResult, derivationScope);
            }
        } else {
            parameterValues = getServerTestAlgorithms();
        }
        if (!TlsParameterIdentifierProvider.isTls13Test(derivationScope)) {
            parameterValues.add(new SigAndHashDerivation(null));
        }
        return parameterValues;
    }

    private List<DerivationParameter<Config, SignatureAndHashAlgorithm>>
            getClientTestDefaultAlgorithms() {
        List<DerivationParameter<Config, SignatureAndHashAlgorithm>> parameterValues =
                new LinkedList<>();
        // the applied algorithm depends on the chosen ciphersuite - see constraints
        // TLS 1.3 clients must send the extension if they expect a server cert
        if (supportsAnyRSA()) {
            parameterValues.add(new SigAndHashDerivation(SignatureAndHashAlgorithm.RSA_SHA1));
        }
        if (supportsAnyECDSA()) {
            parameterValues.add(new SigAndHashDerivation(SignatureAndHashAlgorithm.ECDSA_SHA1));
        }
        if (supportsAnyDSA()) {
            parameterValues.add(new SigAndHashDerivation(SignatureAndHashAlgorithm.DSA_SHA1));
        }

        return parameterValues;
    }

    private boolean supportsAnyRSA() {
        TestContext testContext = TestContext.getInstance();
        return testContext.getFeatureExtractionResult().getCipherSuites().stream()
                .anyMatch(cipherSuite -> cipherSuite.name().contains("RSA"));
    }

    private boolean supportsAnyECDSA() {
        TestContext testContext = TestContext.getInstance();
        return testContext.getFeatureExtractionResult().getCipherSuites().stream()
                .anyMatch(CipherSuite::isECDSA);
    }

    private boolean supportsAnyDSA() {
        TestContext testContext = TestContext.getInstance();
        return testContext.getFeatureExtractionResult().getCipherSuites().stream()
                .anyMatch(CipherSuite::isDSS);
    }

    private List<DerivationParameter<Config, SignatureAndHashAlgorithm>> getClientTestAlgorithms(
            ClientFeatureExtractionResult extractionResult, DerivationScope scope) {
        List<DerivationParameter<Config, SignatureAndHashAlgorithm>> parameterValues =
                new LinkedList<>();
        extractionResult.getAdvertisedSignatureAndHashAlgorithms().stream()
                .filter(
                        algo ->
                                algo.suitedForSigningTls13Messages()
                                        || !TlsParameterIdentifierProvider.isTls13Test(scope))
                .filter(algo -> SignatureAndHashAlgorithm.getImplemented().contains(algo))
                .forEach(algo -> parameterValues.add(new SigAndHashDerivation(algo)));
        return parameterValues;
    }

    private List<DerivationParameter<Config, SignatureAndHashAlgorithm>> getServerTestAlgorithms() {
        // TLS-Scanner has no probe for this yet
        throw new UnsupportedOperationException(
                "SigAndHash derivation is currently not supported for server tests");
    }

    @Override
    public void applyToConfig(Config config, DerivationScope derivationScope) {
        if (getSelectedValue() != null) {
            config.setAutoAdjustSignatureAndHashAlgorithm(false);
            config.setDefaultSelectedSignatureAndHashAlgorithm(getSelectedValue());
            if (context.getConfig().getTestEndpointMode() == TestEndpointType.SERVER) {
                config.setDefaultClientSupportedSignatureAndHashAlgorithms(getSelectedValue());
            } else {
                config.setDefaultServerSupportedSignatureAndHashAlgorithms(getSelectedValue());
            }
        }
    }

    @Override
    public List<ConditionalConstraint> getDefaultConditionalConstraints(
            DerivationScope derivationScope) {

        List<ConditionalConstraint> condConstraints =
                new LinkedList<>(getSharedDefaultConditionalConstraints(derivationScope));

        if (!TlsParameterIdentifierProvider.isTls13Test(derivationScope)) {
            condConstraints.addAll(getDefaultPreTls13Constraints(derivationScope));
        } else {
            condConstraints.add(getHashSizeMustMatchEcdsaPkSizeConstraint());
        }
        return condConstraints;
    }

    public static List<ConditionalConstraint> getDefaultPreTls13Constraints(DerivationScope scope) {
        List<ConditionalConstraint> condConstraints = new LinkedList<>();
        TestContext context = TestContext.getInstance();

        if ((context.getFeatureExtractionResult().getSignatureAndHashAlgorithmsForDerivation()
                        == null
                || context.getFeatureExtractionResult()
                        .getSignatureAndHashAlgorithmsForDerivation()
                        .isEmpty())) {
            condConstraints.add(getDefaultAlgorithmMustMatchCipherSuite());
        }

        condConstraints.add(getMustBeNullForStaticCipherSuite());
        condConstraints.add(getMustNotBeNullForEphemeralCipherSuite());
        return condConstraints;
    }

    public static List<ConditionalConstraint> getSharedDefaultConditionalConstraints(
            DerivationScope scope) {
        List<ConditionalConstraint> condConstraints = new LinkedList<>();
        condConstraints.add(getMustNotBePSSWithShortRSAKeyConstraint());
        condConstraints.add(getMustMatchPkOfCertificateConstraint());
        condConstraints.add(getMustNotBeRSA512withHashAbove256BitsConstraint());
        return condConstraints;
    }

    private ConditionalConstraint getHashSizeMustMatchEcdsaPkSizeConstraint() {
        Set<ParameterIdentifier> requiredDerivations = new HashSet<>();
        requiredDerivations.add(new ParameterIdentifier(TlsParameterType.CERTIFICATE));

        // TLS 1.3 specifies explicit curves for hash functions in ECDSA
        // e.g ecdsa_secp256r1_sha256
        return new ConditionalConstraint(
                requiredDerivations,
                ConstraintBuilder.constrain(
                                getParameterIdentifier().name(),
                                TlsParameterType.CERTIFICATE.name())
                        .by(
                                (SigAndHashDerivation sigAndHashDerivation,
                                        CertificateDerivation certificateDerivation) -> {
                                    if (sigAndHashDerivation.getSelectedValue() != null) {
                                        X509CertificateConfig certConfig =
                                                certificateDerivation.getLeafConfig();
                                        HashAlgorithm hashAlgo =
                                                sigAndHashDerivation
                                                        .getSelectedValue()
                                                        .getHashAlgorithm();
                                        if (!certConfig.getPublicKeyType().isEc()) {
                                            return true;
                                        }
                                        NamedGroup namedGroup =
                                                NamedGroup.convertFromX509NamedCurve(
                                                        certConfig.getDefaultSubjectNamedCurve());
                                        return (namedGroup != NamedGroup.SECP256R1
                                                        || hashAlgo == HashAlgorithm.SHA256)
                                                && (namedGroup != NamedGroup.SECP384R1
                                                        || hashAlgo == HashAlgorithm.SHA384)
                                                && (namedGroup != NamedGroup.SECP521R1
                                                        || hashAlgo == HashAlgorithm.SHA512);
                                    }
                                    return true;
                                }));
    }

    private static ConditionalConstraint getDefaultAlgorithmMustMatchCipherSuite() {
        Set<ParameterIdentifier> requiredDerivations = new HashSet<>();
        requiredDerivations.add(new ParameterIdentifier(TlsParameterType.CIPHER_SUITE));

        // see RFC 5246 - Section 7.4.1.4.1
        return new ConditionalConstraint(
                requiredDerivations,
                ConstraintBuilder.constrain(
                                TlsParameterType.SIG_HASH_ALGORIHTM.name(),
                                TlsParameterType.CIPHER_SUITE.name())
                        .by(
                                (SigAndHashDerivation sigAndHashDerivation,
                                        CipherSuiteDerivation cipherSuiteDerivation) -> {
                                    if (sigAndHashDerivation.getSelectedValue() != null) {
                                        X509PublicKeyType[] requiredCertKeyTypes =
                                                AlgorithmResolver
                                                        .getSuiteableLeafCertificateKeyType(
                                                                cipherSuiteDerivation
                                                                        .getSelectedValue());

                                        for (X509PublicKeyType requiredCertKeyType :
                                                requiredCertKeyTypes) {
                                            switch (requiredCertKeyType) {
                                                case RSASSA_PSS:
                                                case RSA:
                                                    if (sigAndHashDerivation.getSelectedValue()
                                                            != SignatureAndHashAlgorithm.RSA_SHA1) {
                                                        return false;
                                                    }
                                                    break;
                                                case DSA:
                                                    if (sigAndHashDerivation.getSelectedValue()
                                                            != SignatureAndHashAlgorithm.DSA_SHA1) {
                                                        return false;
                                                    }
                                                    break;
                                                case ECDH_ECDSA:
                                                    if (sigAndHashDerivation.getSelectedValue()
                                                            != SignatureAndHashAlgorithm
                                                                    .ECDSA_SHA1) {
                                                        return false;
                                                    }
                                                    break;
                                            }
                                        }
                                    }
                                    return true;
                                }));
    }

    private static ConditionalConstraint getMustBeNullForStaticCipherSuite() {
        Set<ParameterIdentifier> requiredDerivations = new HashSet<>();
        requiredDerivations.add(new ParameterIdentifier(TlsParameterType.CIPHER_SUITE));

        // see RFC 5246 - Section 7.4.1.4.1
        return new ConditionalConstraint(
                requiredDerivations,
                ConstraintBuilder.constrain(
                                TlsParameterType.SIG_HASH_ALGORIHTM.name(),
                                TlsParameterType.CIPHER_SUITE.name())
                        .by(
                                (SigAndHashDerivation sigAndHashDerivation,
                                        CipherSuiteDerivation cipherSuiteDerivation) -> {
                                    if (sigAndHashDerivation.getSelectedValue() != null
                                            && !cipherSuiteDerivation
                                                    .getSelectedValue()
                                                    .isEphemeral()) {
                                        return false;
                                    }
                                    return true;
                                }));
    }

    private static ConditionalConstraint getMustNotBeNullForEphemeralCipherSuite() {
        Set<ParameterIdentifier> requiredDerivations = new HashSet<>();
        requiredDerivations.add(new ParameterIdentifier(TlsParameterType.CIPHER_SUITE));

        // see RFC 5246 - Section 7.4.1.4.1
        return new ConditionalConstraint(
                requiredDerivations,
                ConstraintBuilder.constrain(
                                TlsParameterType.SIG_HASH_ALGORIHTM.name(),
                                TlsParameterType.CIPHER_SUITE.name())
                        .by(
                                (SigAndHashDerivation sigAndHashDerivation,
                                        CipherSuiteDerivation cipherSuiteDerivation) -> {
                                    if (sigAndHashDerivation.getSelectedValue() == null
                                            && cipherSuiteDerivation
                                                    .getSelectedValue()
                                                    .isEphemeral()) {
                                        return false;
                                    }
                                    return true;
                                }));
    }

    private static ConditionalConstraint getMustMatchPkOfCertificateConstraint() {
        Set<ParameterIdentifier> requiredDerivations = new HashSet<>();
        requiredDerivations.add(new ParameterIdentifier(TlsParameterType.CERTIFICATE));

        return new ConditionalConstraint(
                requiredDerivations,
                ConstraintBuilder.constrain(
                                TlsParameterType.SIG_HASH_ALGORIHTM.name(),
                                TlsParameterType.CERTIFICATE.name())
                        .by(
                                (SigAndHashDerivation sigAndHashDerivation,
                                        CertificateDerivation certificateDerivation) -> {
                                    if (sigAndHashDerivation.getSelectedValue() != null) {
                                        SignatureAndHashAlgorithm signatureAndHashAlgorithm =
                                                sigAndHashDerivation.getSelectedValue();
                                        SignatureAlgorithm sigAlg =
                                                signatureAndHashAlgorithm.getSignatureAlgorithm();
                                        X509CertificateConfig config =
                                                certificateDerivation.getLeafConfig();
                                        switch (config.getPublicKeyType()) {
                                            case ECDH_ONLY:
                                            case ECDH_ECDSA:
                                                if (sigAlg != SignatureAlgorithm.ECDSA) {
                                                    return false;
                                                }
                                                break;
                                            case RSASSA_PSS:
                                                if (!signatureAndHashAlgorithm
                                                        .name()
                                                        .startsWith("RSA_PSS_PSS")) {
                                                    return false;
                                                }
                                                break;
                                            case RSA:
                                                if (sigAlg != SignatureAlgorithm.RSA_PKCS1
                                                        && !signatureAndHashAlgorithm
                                                                .name()
                                                                .startsWith("RSA_PSS_RSAE")) {
                                                    return false;
                                                }
                                                break;
                                            case DSA:
                                                if (sigAlg != SignatureAlgorithm.DSA) {
                                                    return false;
                                                }
                                                break;
                                            case GOST_R3411_2001:
                                                if (sigAlg != SignatureAlgorithm.GOSTR34102001) {
                                                    return false;
                                                }
                                                break;
                                            case GOST_R3411_2012:
                                                if (sigAlg != SignatureAlgorithm.GOSTR34102012_256
                                                        && sigAlg
                                                                != SignatureAlgorithm
                                                                        .GOSTR34102012_512) {
                                                    return false;
                                                }
                                                break;
                                            default:
                                                throw new RuntimeException(
                                                        "Encountered unsupported certificate public key type "
                                                                + config.getPublicKeyType());
                                        }
                                    }
                                    return true;
                                }));
    }

    private static ConditionalConstraint getMustNotBePSSWithShortRSAKeyConstraint() {
        Set<ParameterIdentifier> requiredDerivations = new HashSet<>();
        requiredDerivations.add(new ParameterIdentifier(TlsParameterType.CERTIFICATE));

        // RSA 512 bit key does not suffice for PSS signature
        return new ConditionalConstraint(
                requiredDerivations,
                ConstraintBuilder.constrain(
                                TlsParameterType.SIG_HASH_ALGORIHTM.name(),
                                TlsParameterType.CERTIFICATE.name())
                        .by(
                                (SigAndHashDerivation sigAndHashDerivation,
                                        CertificateDerivation certificateDerivation) -> {
                                    if (sigAndHashDerivation.getSelectedValue() != null) {
                                        SignatureAlgorithm sigAlg =
                                                sigAndHashDerivation
                                                        .getSelectedValue()
                                                        .getSignatureAlgorithm();
                                        HashAlgorithm hashAlgo =
                                                sigAndHashDerivation
                                                        .getSelectedValue()
                                                        .getHashAlgorithm();
                                        X509CertificateConfig selectCertConfig =
                                                certificateDerivation.getLeafConfig();

                                        if (sigAlg.name().contains("PSS")) {
                                            if (selectCertConfig.getRsaModulus().bitLength()
                                                    < 1024) {
                                                return false;
                                            } else
                                                return hashAlgo != HashAlgorithm.SHA512
                                                        || selectCertConfig
                                                                        .getRsaModulus()
                                                                        .bitLength()
                                                                >= 2048;
                                        }
                                    }
                                    return true;
                                }));
    }

    private static ConditionalConstraint getMustNotBeRSA512withHashAbove256BitsConstraint() {
        Set<ParameterIdentifier> requiredDerivations = new HashSet<>();
        requiredDerivations.add(new ParameterIdentifier(TlsParameterType.CERTIFICATE));

        // RSA 512 bit key does not work with RSA_SHA[> 256]
        return new ConditionalConstraint(
                requiredDerivations,
                ConstraintBuilder.constrain(
                                TlsParameterType.SIG_HASH_ALGORIHTM.name(),
                                TlsParameterType.CERTIFICATE.name())
                        .by(
                                (SigAndHashDerivation sigAndHashDerivation,
                                        CertificateDerivation certificateDerivation) -> {
                                    if (sigAndHashDerivation.getSelectedValue() != null) {
                                        SignatureAlgorithm sigAlg =
                                                sigAndHashDerivation
                                                        .getSelectedValue()
                                                        .getSignatureAlgorithm();
                                        HashAlgorithm hashAlgo =
                                                sigAndHashDerivation
                                                        .getSelectedValue()
                                                        .getHashAlgorithm();
                                        X509CertificateConfig selectedCertConfig =
                                                certificateDerivation.getLeafConfig();

                                        return selectedCertConfig.getRsaModulus().bitLength()
                                                        >= 1024
                                                || !sigAlg.name().contains("RSA")
                                                || !isSHAHashLongerThan256Bits(hashAlgo);
                                    }
                                    return true;
                                }));
    }

    private static boolean isSHAHashLongerThan256Bits(HashAlgorithm hashAlgo) {
        switch (hashAlgo) {
            case SHA384:
            case SHA512:
                return true;
            default:
                return false;
        }
    }

    @Override
    protected TlsDerivationParameter<SignatureAndHashAlgorithm> generateValue(
            SignatureAndHashAlgorithm selectedValue) {
        return new SigAndHashDerivation(selectedValue);
    }
}
