package de.rub.nds.tlstest.framework.model.derivationParameter;

import de.rub.nds.tlsattacker.core.certificate.CertificateByteChooser;
import de.rub.nds.tlsattacker.core.certificate.CertificateKeyPair;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CertificateKeyType;
import de.rub.nds.tlsattacker.core.constants.HashAlgorithm;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.SignatureAlgorithm;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.crypto.keys.CustomDSAPrivateKey;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.model.DerivationScope;
import de.rub.nds.tlstest.framework.model.DerivationType;
import de.rub.nds.tlstest.framework.model.constraint.ConditionalConstraint;
import de.rub.nds.tlstest.framework.model.constraint.ConstraintHelper;
import de.rwth.swc.coffee4j.model.constraints.ConstraintBuilder;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Provides a modification bitmask for ServerKeyExchange and CertificateVerify
 * signatures.
 */
public class SignatureBitmaskDerivation extends DerivationParameter<Integer> {

    public SignatureBitmaskDerivation() {
        super(DerivationType.SIGNATURE_BITMASK, Integer.class);
    }

    public SignatureBitmaskDerivation(Integer selectedValue) {
        this();
        setSelectedValue(selectedValue);
    }

    @Override
    public List<DerivationParameter> getParameterValues(TestContext context, DerivationScope scope) {
        return getFirstAndLastByteOfEachSignature(context, scope);
    }

    private List<DerivationParameter> getAllPossibleBytePositions(TestContext context, DerivationScope scope) {
        List<DerivationParameter> parameterValues = new LinkedList<>();
        int maxSignatureLength = getMaxSignatureByteLength(context, scope);

        for (int i = 0; i < maxSignatureLength; i++) {
            parameterValues.add(new SignatureBitmaskDerivation(i));
        }
        return parameterValues;
    }

    private List<DerivationParameter> getFirstAndLastByteOfEachSignature(TestContext context, DerivationScope scope) {
        Set<Integer> listedValues = new HashSet<>();
        listedValues.add(0);

        List<DerivationParameter> applicableCertificates = DerivationFactory.getInstance(DerivationType.CERTIFICATE).getConstrainedParameterValues(context, scope);
        applicableCertificates.forEach(selectableCert -> listedValues.add(computeSignatureSizeForCertKeyPair((CertificateKeyPair) selectableCert.getSelectedValue()) - 1));
        
        List<DerivationParameter> parameterValues = new LinkedList<>();
        listedValues.forEach(position -> parameterValues.add(new SignatureBitmaskDerivation(position)));
        return parameterValues;
    }

    private int getMaxSignatureByteLength(TestContext context, DerivationScope scope) {
        List<SignatureAndHashAlgorithm> signatureAndHashAlgorithms;
        if (context.getSiteReport().getSupportedSignatureAndHashAlgorithms() != null) {
            signatureAndHashAlgorithms = context.getSiteReport().getSupportedSignatureAndHashAlgorithms()
                    .stream().filter(algorithm -> SignatureAndHashAlgorithm.getImplemented().contains(algorithm))
                    .collect(Collectors.toList());

            if (signatureAndHashAlgorithms.size() == 0) {
                throw new RuntimeException("No supported SignatureAndHashAlgorithm offered by target");
            }
        } else {
            signatureAndHashAlgorithms = new LinkedList<>();
            //TLS 1.2 default algorithms
            signatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_SHA1);
            signatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.DSA_SHA1);
            signatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.ECDSA_SHA1);
        }

        int maxSignatureLength = 0;
        for (SignatureAndHashAlgorithm signatureHashAlgorithm : signatureAndHashAlgorithms) {
            int estimatedMaxSignatureLength = computeEstimatedMaxSignatureSize(signatureHashAlgorithm);
            if (estimatedMaxSignatureLength > maxSignatureLength) {
                maxSignatureLength = estimatedMaxSignatureLength;
            }
        }

        return maxSignatureLength;
    }

    private static int getMaxPublicKeySizeForType(CertificateKeyType requiredPublicKeyType) {
        List<CertificateKeyPair> certificateKeyPairs = CertificateByteChooser.getInstance().getCertificateKeyPairList();
        int pkSize = 0;
        for (CertificateKeyPair certKeyPair : certificateKeyPairs) {
            if (requiredPublicKeyType != CertificateKeyType.DSS && certKeyPair.getCertPublicKeyType() == requiredPublicKeyType && certKeyPair.getPublicKey().keySize() > pkSize) {
                pkSize = certKeyPair.getPublicKey().keySize();
            } else if(requiredPublicKeyType == CertificateKeyType.DSS && certKeyPair.getCertPublicKeyType() == requiredPublicKeyType && ((CustomDSAPrivateKey)certKeyPair.getPrivateKey()).getParams().getQ().bitLength() > pkSize) {
                pkSize = ((CustomDSAPrivateKey)certKeyPair.getPrivateKey()).getParams().getQ().bitLength(); 
            }
        }
        return pkSize;
    }

    private static int getMaxNamedGroupSize() {
        TestContext context = TestContext.getInstance();
        List<NamedGroup> supportedNamedGroups = context.getSiteReport().getSupportedNamedGroups().stream()
                .filter(group -> NamedGroup.getImplemented().contains(group)).collect(Collectors.toList());
        NamedGroup biggestNamedGroup = null;
        for (NamedGroup group : supportedNamedGroups) {
            if (biggestNamedGroup == null || biggestNamedGroup.getCoordinateSizeInBit() < group.getCoordinateSizeInBit()) {
                biggestNamedGroup = group;
            }
        }
        return biggestNamedGroup.getCoordinateSizeInBit();
    }

    @Override
    public void applyToConfig(Config config, TestContext context) {
    }

    public static int computeEstimatedMaxSignatureSize(SignatureAndHashAlgorithm signatureHashAlgorithm) {
        SignatureAlgorithm signatureAlgorithm = signatureHashAlgorithm.getSignatureAlgorithm();
        if (signatureAlgorithm.name().contains("RSA")) {
            return computeEstimatedSignatureSize(signatureAlgorithm, getMaxPublicKeySizeForType(CertificateKeyType.RSA));
        } else if (signatureAlgorithm == SignatureAlgorithm.ECDSA) {
            return computeEstimatedSignatureSize(signatureAlgorithm, getMaxNamedGroupSize());
        } else if (signatureAlgorithm == SignatureAlgorithm.DSA) {
            return computeEstimatedSignatureSize(signatureAlgorithm, getMaxPublicKeySizeForType(CertificateKeyType.DSS));
        } else {
            throw new RuntimeException("Can not compute maximum signature size for SignatureAlgorithm " + signatureAlgorithm);
        }
    }

    public static Integer computeEstimatedSignatureSize(SignatureAlgorithm signatureAlgorithm, int pkSize) {
        int pkByteSize = (int) Math.ceil((double) pkSize / 8);
        switch (signatureAlgorithm) {
            case RSA:
            case RSA_PSS_PSS:
            case RSA_PSS_RSAE:
                return pkByteSize;
            case DSA:
                //signature size is (#bits of Q) / 4
                return (pkSize / 4) + 6; //+6 bytes because of DER (see below)
            case ECDSA:
                //signature consists of tag || length || type || length || r
                //                                    || type || length || s
                //DER encoding may add an additional byte if the MSB of r or s is 1
                //we do not include these as we can't know beforehand 
                int signatureLength = 6 + 2 * pkByteSize;
                if (pkSize == 521) {
                    //SECP521R1 encoding differs from other groups
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
                return computeEstimatedSignatureSize(SignatureAlgorithm.RSA, certKeyPair.getPublicKey().keySize());
            case ECDH:
            case ECDSA:
                return computeEstimatedSignatureSize(SignatureAlgorithm.ECDSA, certKeyPair.getPublicKey().keySize());
            case DSS:
                return computeEstimatedSignatureSize(SignatureAlgorithm.DSA, ((CustomDSAPrivateKey)certKeyPair.getPrivateKey()).getParams().getQ().bitLength());
            default:
                throw new RuntimeException("Can not compute signature size for CertPublicKeyType " + certKeyPair.getCertPublicKeyType());
        }
    }

    @Override
    public List<ConditionalConstraint> getDefaultConditionalConstraints(DerivationScope scope) {
        List<ConditionalConstraint> conditionalConstraints = new LinkedList<>();
        if (ConstraintHelper.signatureLengthConstraintApplicable(scope)) {
            conditionalConstraints.add(getMustBeWithinSignatureSizeConstraint());
        }
        return conditionalConstraints;
    }

    private ConditionalConstraint getMustBeWithinSignatureSizeConstraint() {
        Set<DerivationType> requiredDerivations = new HashSet<>();
        requiredDerivations.add(DerivationType.CERTIFICATE);
        requiredDerivations.add(DerivationType.SIG_HASH_ALGORIHTM);

        return new ConditionalConstraint(requiredDerivations, ConstraintBuilder.constrain(getType().name(), DerivationType.CERTIFICATE.name(), DerivationType.SIG_HASH_ALGORIHTM.name()).by((DerivationParameter bitmaskParam, DerivationParameter certParam, DerivationParameter sigHashAlgorithmParam) -> {
            SignatureBitmaskDerivation bitmaskDerivation = (SignatureBitmaskDerivation) bitmaskParam;
            SigAndHashDerivation sigHashAlg = (SigAndHashDerivation) sigHashAlgorithmParam;
            
            if(sigHashAlg.getSelectedValue() == null) {
                return false;
            }
            
            CertificateDerivation cert = (CertificateDerivation) certParam;

            int certificateKeySize; 
            if(cert.getSelectedValue().getCertPublicKeyType() == CertificateKeyType.DSS) {
                certificateKeySize = ((CustomDSAPrivateKey)cert.getSelectedValue().getPrivateKey()).getParams().getQ().bitLength();
            } else {
                certificateKeySize = cert.getSelectedValue().getPublicKey().keySize(); 
            }
            SignatureAlgorithm sigAlg = sigHashAlg.getSelectedValue().getSignatureAlgorithm();

            return computeEstimatedSignatureSize(sigAlg, certificateKeySize) > bitmaskDerivation.getSelectedValue();
        }));
    }

}
