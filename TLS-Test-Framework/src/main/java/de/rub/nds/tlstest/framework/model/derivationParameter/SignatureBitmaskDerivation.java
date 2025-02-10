/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.model.derivationParameter;

import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.constraint.ConditionalConstraint;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.model.parameter.ParameterIdentifier;
import de.rub.nds.anvilcore.model.parameter.ParameterScope;
import de.rub.nds.protocol.constants.SignatureAlgorithm;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.anvil.TlsDerivationParameter;
import de.rub.nds.tlstest.framework.model.TlsParameterType;
import de.rub.nds.tlstest.framework.utils.X509CertificateConfigContainer;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.constants.X509PublicKeyType;
import de.rwth.swc.coffee4j.model.constraints.ConstraintBuilder;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import org.apache.commons.lang3.NotImplementedException;

/** Provides a modification bitmask for ServerKeyExchange and CertificateVerify signatures. */
public class SignatureBitmaskDerivation extends TlsDerivationParameter<Integer> {

    public SignatureBitmaskDerivation() {
        super(TlsParameterType.SIGNATURE_BITMASK, Integer.class);
    }

    public SignatureBitmaskDerivation(Integer selectedValue) {
        this();
        setSelectedValue(selectedValue);
    }

    @Override
    public List<DerivationParameter<Config, Integer>> getParameterValues(
            DerivationScope derivationScope) {
        return getFirstAndLastByteOfEachSignature(context, derivationScope);
    }

    private List<DerivationParameter<Config, Integer>> getAllPossibleBytePositions(
            TestContext context, DerivationScope scope) {
        List<DerivationParameter<Config, Integer>> parameterValues = new LinkedList<>();
        int maxSignatureLength = getMaxSignatureByteLength(context, scope);

        for (int i = 0; i < maxSignatureLength; i++) {
            parameterValues.add(new SignatureBitmaskDerivation(i));
        }
        return parameterValues;
    }

    private List<DerivationParameter<Config, Integer>> getFirstAndLastByteOfEachSignature(
            TestContext context, DerivationScope scope) {
        Set<Integer> listedValues = new HashSet<>();
        listedValues.add(0);

        List<DerivationParameter<Config, X509CertificateConfig>> applicableCertificates =
                TlsParameterType.CERTIFICATE
                        .getInstance(ParameterScope.NO_SCOPE)
                        .getConstrainedParameterValues(scope);
        applicableCertificates.forEach(
                selectableCert ->
                        listedValues.add(
                                computeSignatureSizeForCertConfig(selectableCert.getSelectedValue())
                                        - 1));

        List<DerivationParameter<Config, Integer>> parameterValues = new LinkedList<>();
        listedValues.forEach(
                position -> parameterValues.add(new SignatureBitmaskDerivation(position)));
        return parameterValues;
    }

    private int getMaxSignatureByteLength(TestContext context, DerivationScope scope) {
        List<SignatureAndHashAlgorithm> signatureAndHashAlgorithms;
        if (!context.getFeatureExtractionResult()
                .getSignatureAndHashAlgorithmsForDerivation()
                .isEmpty()) {
            signatureAndHashAlgorithms =
                    context
                            .getFeatureExtractionResult()
                            .getSignatureAndHashAlgorithmsForDerivation()
                            .stream()
                            .filter(
                                    algorithm ->
                                            SignatureAndHashAlgorithm.getImplemented()
                                                    .contains(algorithm))
                            .collect(Collectors.toList());
        } else {
            signatureAndHashAlgorithms = new LinkedList<>();
            // TLS 1.2 default algorithms
            signatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_SHA1);
            signatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.DSA_SHA1);
            signatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.ECDSA_SHA1);
        }

        int maxSignatureLength = 0;
        for (SignatureAndHashAlgorithm signatureHashAlgorithm : signatureAndHashAlgorithms) {
            int estimatedMaxSignatureLength =
                    computeEstimatedMaxSignatureSize(signatureHashAlgorithm);
            if (estimatedMaxSignatureLength > maxSignatureLength) {
                maxSignatureLength = estimatedMaxSignatureLength;
            }
        }

        return maxSignatureLength;
    }

    private static int getMaxPublicKeySizeForType(X509PublicKeyType requiredPublicKeyType) {
        List<X509CertificateConfig> certConfigs =
                X509CertificateConfigContainer.getInstance().getCertConfigs();
        int pkSize = 0;
        for (X509CertificateConfig certConfig : certConfigs) {
            if (certConfig.getPublicKeyType() != requiredPublicKeyType) {
                continue;
            }
            switch (requiredPublicKeyType) {
                case RSA:
                    pkSize = Math.max(pkSize, certConfig.getRsaModulus().bitLength());
                    break;
                case DH:
                    pkSize = Math.max(pkSize, certConfig.getDhModulus().bitLength());
                    break;
                case ECDH_ECDSA:
                case ECDH_ONLY:
                case ECMQV:
                case ED25519:
                case ED448:
                case GOST_R3411_2001:
                case GOST_R3411_94:
                case GOST_R3411_2012:
                case X25519:
                case X448:
                    pkSize =
                            Math.max(
                                    pkSize,
                                    certConfig.getDefaultSubjectNamedCurve().getBitLength());
                    break;
                case DSA:
                    pkSize = Math.max(pkSize, certConfig.getDsaPrimeQ().bitLength());
                    break;
                default:
                    throw new NotImplementedException(
                            requiredPublicKeyType.name() + " not implemented");
            }
        }
        return pkSize;
    }

    private static int getMaxNamedGroupSize() {
        TestContext context = TestContext.getInstance();
        List<NamedGroup> supportedNamedGroups =
                context.getFeatureExtractionResult().getNamedGroups().stream()
                        .filter(group -> NamedGroup.getImplemented().contains(group))
                        .filter(NamedGroup::isEcGroup)
                        .collect(Collectors.toList());
        NamedGroup biggestNamedGroup = null;
        for (NamedGroup group : supportedNamedGroups) {
            if (biggestNamedGroup == null
                    || biggestNamedGroup.convertToX509().getBitLength()
                            < group.convertToX509().getBitLength()) {
                biggestNamedGroup = group;
            }
        }
        assert biggestNamedGroup != null;
        return biggestNamedGroup.convertToX509().getBitLength();
    }

    @Override
    public void applyToConfig(Config config, DerivationScope derivationScope) {}

    public static int computeEstimatedMaxSignatureSize(
            SignatureAndHashAlgorithm signatureHashAlgorithm) {
        SignatureAlgorithm signatureAlgorithm = signatureHashAlgorithm.getSignatureAlgorithm();
        if (signatureAlgorithm.name().contains("RSA")) {
            return computeEstimatedSignatureSize(
                    signatureAlgorithm, getMaxPublicKeySizeForType(X509PublicKeyType.RSA));
        } else if (signatureAlgorithm == SignatureAlgorithm.ECDSA) {
            return computeEstimatedSignatureSize(signatureAlgorithm, getMaxNamedGroupSize());
        } else if (signatureAlgorithm == SignatureAlgorithm.DSA) {
            return computeEstimatedSignatureSize(
                    signatureAlgorithm, getMaxPublicKeySizeForType(X509PublicKeyType.DSA));
        } else {
            throw new RuntimeException(
                    "Can not compute maximum signature size for SignatureAlgorithm "
                            + signatureAlgorithm);
        }
    }

    public static Integer computeEstimatedSignatureSize(
            SignatureAlgorithm signatureAlgorithm, int pkSize) {
        int pkByteSize = (int) Math.ceil((double) pkSize / 8);
        switch (signatureAlgorithm) {
            case RSA_PKCS1:
            case RSA_SSA_PSS:
                return pkByteSize;
            case DSA:
                // signature size is (#bits of Q) / 4
                return (pkSize / 4) + 6; // +6 bytes because of DER (see below)
            case ECDSA:
                // signature consists of tag || length || type || length || r
                //                                    || type || length || s
                // DER encoding may add an additional byte if the MSB of r or s is 1
                // we do not include these as we can't know beforehand
                int signatureLength = 6 + 2 * pkByteSize;
                if (pkSize == 521) {
                    signatureLength -= 1;
                }
                return signatureLength;
            default:
                return null;
        }
    }

    public static Integer computeSignatureSizeForCertConfig(X509CertificateConfig certConfig) {
        switch (certConfig.getPublicKeyType()) {
            case RSA:
                return computeEstimatedSignatureSize(
                        SignatureAlgorithm.RSA_PKCS1, certConfig.getRsaModulus().bitLength());
            case ECDH_ONLY:
            case ECDH_ECDSA:
                return computeEstimatedSignatureSize(
                        SignatureAlgorithm.ECDSA,
                        certConfig.getDefaultSubjectNamedCurve().getBitLength());
            case DSA:
                return computeEstimatedSignatureSize(
                        SignatureAlgorithm.DSA, certConfig.getDsaPrimeQ().bitLength());
            default:
                throw new RuntimeException(
                        "Can not compute signature size for CertPublicKeyType "
                                + certConfig.getPublicKeyType());
        }
    }

    @Override
    public List<ConditionalConstraint> getDefaultConditionalConstraints(
            DerivationScope derivationScope) {
        List<ConditionalConstraint> conditionalConstraints = new LinkedList<>();
        conditionalConstraints.add(getMustBeWithinSignatureSizeConstraint());
        return conditionalConstraints;
    }

    private ConditionalConstraint getMustBeWithinSignatureSizeConstraint() {
        Set<ParameterIdentifier> requiredDerivations = new HashSet<>();
        requiredDerivations.add(new ParameterIdentifier(TlsParameterType.CERTIFICATE));
        requiredDerivations.add(new ParameterIdentifier(TlsParameterType.SIG_HASH_ALGORIHTM));

        return new ConditionalConstraint(
                requiredDerivations,
                ConstraintBuilder.constrain(
                                getParameterIdentifier().name(),
                                TlsParameterType.CERTIFICATE.name(),
                                TlsParameterType.SIG_HASH_ALGORIHTM.name())
                        .by(
                                (SignatureBitmaskDerivation signatureBitmaskDerivation,
                                        CertificateDerivation certificateDerivation,
                                        SigAndHashDerivation sigAndHashDerivation) -> {
                                    int selectedBitmaskBytePosition =
                                            signatureBitmaskDerivation.getSelectedValue();
                                    X509CertificateConfig certConfig =
                                            certificateDerivation.getSelectedValue();
                                    SignatureAndHashAlgorithm selectedSigHashAlgorithm =
                                            sigAndHashDerivation.getSelectedValue();

                                    if (selectedSigHashAlgorithm == null) {
                                        return false;
                                    }

                                    int certificateKeySize;
                                    switch (certConfig.getPublicKeyType()) {
                                        case RSA:
                                        case RSASSA_PSS:
                                        case RSAES_OAEP:
                                            certificateKeySize =
                                                    certConfig.getRsaModulus().bitLength();
                                            break;
                                        case ECDH_ECDSA:
                                        case ECDH_ONLY:
                                        case ECMQV:
                                        case ED25519:
                                        case ED448:
                                        case GOST_R3411_2001:
                                        case GOST_R3411_94:
                                        case GOST_R3411_2012:
                                        case X25519:
                                        case X448:
                                            certificateKeySize =
                                                    certConfig
                                                            .getDefaultSubjectNamedCurve()
                                                            .getBitLength();
                                            break;
                                        case DH:
                                            certificateKeySize =
                                                    certConfig.getDhModulus().bitLength();
                                            break;
                                        case DSA:
                                            certificateKeySize =
                                                    certConfig.getDsaPrimeQ().bitLength();
                                            break;
                                        default:
                                            throw new NotImplementedException(
                                                    certConfig.getPublicKeyType().name()
                                                            + " not implemented");
                                    }
                                    SignatureAlgorithm sigAlg =
                                            selectedSigHashAlgorithm.getSignatureAlgorithm();

                                    return computeEstimatedSignatureSize(sigAlg, certificateKeySize)
                                            > selectedBitmaskBytePosition;
                                }));
    }

    @Override
    protected TlsDerivationParameter<Integer> generateValue(Integer selectedValue) {
        return new SignatureBitmaskDerivation(selectedValue);
    }
}
