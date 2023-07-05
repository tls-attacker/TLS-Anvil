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
import de.rub.nds.tlsattacker.core.certificate.CertificateByteChooser;
import de.rub.nds.tlsattacker.core.certificate.CertificateKeyPair;
import de.rub.nds.tlsattacker.core.constants.CertificateKeyType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.SignatureAlgorithm;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.crypto.keys.CustomDSAPrivateKey;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.anvil.TlsAnvilConfig;
import de.rub.nds.tlstest.framework.anvil.TlsDerivationParameter;
import de.rub.nds.tlstest.framework.model.LegacyDerivationScope;
import de.rub.nds.tlstest.framework.model.TlsParameterType;
import de.rub.nds.tlstest.framework.model.constraint.ConstraintHelper;
import de.rwth.swc.coffee4j.model.constraints.ConstraintBuilder;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

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
    public List<DerivationParameter<TlsAnvilConfig, Integer>> getParameterValues(
            DerivationScope derivationScope) {
        return getFirstAndLastByteOfEachSignature(context, derivationScope);
    }

    private List<DerivationParameter<TlsAnvilConfig, Integer>> getAllPossibleBytePositions(
            TestContext context, LegacyDerivationScope scope) {
        List<DerivationParameter<TlsAnvilConfig, Integer>> parameterValues = new LinkedList<>();
        int maxSignatureLength = getMaxSignatureByteLength(context, scope);

        for (int i = 0; i < maxSignatureLength; i++) {
            parameterValues.add(new SignatureBitmaskDerivation(i));
        }
        return parameterValues;
    }

    private List<DerivationParameter<TlsAnvilConfig, Integer>> getFirstAndLastByteOfEachSignature(
            TestContext context, DerivationScope scope) {
        Set<Integer> listedValues = new HashSet<>();
        listedValues.add(0);

        List<DerivationParameter<TlsAnvilConfig, CertificateKeyPair>> applicableCertificates =
                DerivationFactory.getInstance(TlsParameterType.CERTIFICATE)
                        .getConstrainedParameterValues(scope);
        applicableCertificates.forEach(
                selectableCert ->
                        listedValues.add(
                                computeSignatureSizeForCertKeyPair(
                                                (CertificateKeyPair)
                                                        selectableCert.getSelectedValue())
                                        - 1));

        List<DerivationParameter<TlsAnvilConfig, Integer>> parameterValues = new LinkedList<>();
        listedValues.forEach(
                position -> parameterValues.add(new SignatureBitmaskDerivation(position)));
        return parameterValues;
    }

    private int getMaxSignatureByteLength(TestContext context, LegacyDerivationScope scope) {
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

    private static int getMaxPublicKeySizeForType(CertificateKeyType requiredPublicKeyType) {
        List<CertificateKeyPair> certificateKeyPairs =
                CertificateByteChooser.getInstance().getCertificateKeyPairList();
        int pkSize = 0;
        for (CertificateKeyPair certKeyPair : certificateKeyPairs) {
            if (requiredPublicKeyType != CertificateKeyType.DSS
                    && certKeyPair.getCertPublicKeyType() == requiredPublicKeyType
                    && certKeyPair.getPublicKey().keySize() > pkSize) {
                pkSize = certKeyPair.getPublicKey().keySize();
            } else if (requiredPublicKeyType == CertificateKeyType.DSS
                    && certKeyPair.getCertPublicKeyType() == requiredPublicKeyType
                    && ((CustomDSAPrivateKey) certKeyPair.getPrivateKey())
                                    .getParams()
                                    .getQ()
                                    .bitLength()
                            > pkSize) {
                pkSize =
                        ((CustomDSAPrivateKey) certKeyPair.getPrivateKey())
                                .getParams()
                                .getQ()
                                .bitLength();
            }
        }
        return pkSize;
    }

    private static int getMaxNamedGroupSize() {
        TestContext context = TestContext.getInstance();
        List<NamedGroup> supportedNamedGroups =
                context.getFeatureExtractionResult().getNamedGroups().stream()
                        .filter(group -> NamedGroup.getImplemented().contains(group))
                        .collect(Collectors.toList());
        NamedGroup biggestNamedGroup = null;
        for (NamedGroup group : supportedNamedGroups) {
            if (biggestNamedGroup == null
                    || biggestNamedGroup.getCoordinateSizeInBit()
                            < group.getCoordinateSizeInBit()) {
                biggestNamedGroup = group;
            }
        }
        return biggestNamedGroup.getCoordinateSizeInBit();
    }

    @Override
    public void applyToConfig(TlsAnvilConfig config, DerivationScope derivationScope) {}

    public static int computeEstimatedMaxSignatureSize(
            SignatureAndHashAlgorithm signatureHashAlgorithm) {
        SignatureAlgorithm signatureAlgorithm = signatureHashAlgorithm.getSignatureAlgorithm();
        if (signatureAlgorithm.name().contains("RSA")) {
            return computeEstimatedSignatureSize(
                    signatureAlgorithm, getMaxPublicKeySizeForType(CertificateKeyType.RSA));
        } else if (signatureAlgorithm == SignatureAlgorithm.ECDSA) {
            return computeEstimatedSignatureSize(signatureAlgorithm, getMaxNamedGroupSize());
        } else if (signatureAlgorithm == SignatureAlgorithm.DSA) {
            return computeEstimatedSignatureSize(
                    signatureAlgorithm, getMaxPublicKeySizeForType(CertificateKeyType.DSS));
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
            case RSA:
            case RSA_PSS_PSS:
            case RSA_PSS_RSAE:
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

    public static Integer computeSignatureSizeForCertKeyPair(CertificateKeyPair certKeyPair) {
        switch (certKeyPair.getCertPublicKeyType()) {
            case RSA:
                return computeEstimatedSignatureSize(
                        SignatureAlgorithm.RSA, certKeyPair.getPublicKey().keySize());
            case ECDH:
            case ECDSA:
                return computeEstimatedSignatureSize(
                        SignatureAlgorithm.ECDSA, certKeyPair.getPublicKey().keySize());
            case DSS:
                return computeEstimatedSignatureSize(
                        SignatureAlgorithm.DSA,
                        ((CustomDSAPrivateKey) certKeyPair.getPrivateKey())
                                .getParams()
                                .getQ()
                                .bitLength());
            default:
                throw new RuntimeException(
                        "Can not compute signature size for CertPublicKeyType "
                                + certKeyPair.getCertPublicKeyType());
        }
    }

    @Override
    public List<ConditionalConstraint> getDefaultConditionalConstraints(
            DerivationScope derivationScope) {
        List<ConditionalConstraint> conditionalConstraints = new LinkedList<>();
        if (ConstraintHelper.signatureLengthConstraintApplicable(derivationScope)) {
            conditionalConstraints.add(getMustBeWithinSignatureSizeConstraint());
        }
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
                                    CertificateKeyPair selectedCertKeyPair =
                                            certificateDerivation.getSelectedValue();
                                    SignatureAndHashAlgorithm selectedSigHashAlgorithm =
                                            sigAndHashDerivation.getSelectedValue();

                                    if (selectedSigHashAlgorithm == null) {
                                        return false;
                                    }

                                    int certificateKeySize;
                                    if (selectedCertKeyPair.getCertPublicKeyType()
                                            == CertificateKeyType.DSS) {
                                        certificateKeySize =
                                                ((CustomDSAPrivateKey)
                                                                selectedCertKeyPair.getPrivateKey())
                                                        .getParams()
                                                        .getQ()
                                                        .bitLength();
                                    } else {
                                        certificateKeySize =
                                                selectedCertKeyPair.getPublicKey().keySize();
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
