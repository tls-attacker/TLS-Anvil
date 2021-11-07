package de.rub.nds.tlstest.framework.model.derivationParameter;

import de.rub.nds.tlsattacker.core.certificate.CertificateKeyPair;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CertificateKeyType;
import de.rub.nds.tlsattacker.core.constants.HashAlgorithm;
import de.rub.nds.tlsattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.SignatureAlgorithm;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.constants.TestEndpointType;
import de.rub.nds.tlstest.framework.model.DerivationScope;
import de.rub.nds.tlstest.framework.model.DerivationType;
import de.rub.nds.tlstest.framework.model.constraint.ConditionalConstraint;
import de.rub.nds.tlstest.framework.model.constraint.ConstraintHelper;
import de.rwth.swc.coffee4j.model.constraints.ConstraintBuilder;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

/**
 *
 */
public class SigAndHashDerivation extends DerivationParameter<SignatureAndHashAlgorithm> {

    public SigAndHashDerivation() {
        super(DerivationType.SIG_HASH_ALGORIHTM, SignatureAndHashAlgorithm.class);
    }

    public SigAndHashDerivation(SignatureAndHashAlgorithm selectedValue) {
        this();
        setSelectedValue(selectedValue);
    }

    @Override
    public List<DerivationParameter> getParameterValues(TestContext context, DerivationScope scope) {
        List<DerivationParameter> parameterValues = new LinkedList<>();
        if (context.getConfig().getTestEndpointMode() == TestEndpointType.CLIENT) {
            if (context.getSiteReport().getSupportedSignatureAndHashAlgorithms() == null) {
                parameterValues = getClientTestDefaultAlgorithms();
            } else {
                parameterValues = getClientTestAlgorithms(context, scope);
            }
        } else {
            parameterValues = getServerTestAlgorithms();
        }
        if (!scope.isTls13Test()) {
            parameterValues.add(new SigAndHashDerivation(null));
        }
        return parameterValues;
    }

    private List<DerivationParameter> getClientTestDefaultAlgorithms() {
        List<DerivationParameter> parameterValues = new LinkedList<>();
        //the applied algorithm depends on the chosen ciphersuite - see constraints
        //TLS 1.3 clients must send the extension if they expect a server cert
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
        return testContext.getSiteReport().getCipherSuites().stream()
                .anyMatch(cipherSuite -> cipherSuite.name().contains("RSA"));
    }

    private boolean supportsAnyECDSA() {
        TestContext testContext = TestContext.getInstance();
        return testContext.getSiteReport().getCipherSuites().stream()
                .anyMatch(cipherSuite -> cipherSuite.isECDSA());
    }

    private boolean supportsAnyDSA() {
        TestContext testContext = TestContext.getInstance();
        return testContext.getSiteReport().getCipherSuites().stream()
                .anyMatch(cipherSuite -> cipherSuite.isDSS());
    }

    private List<DerivationParameter> getClientTestAlgorithms(TestContext context, DerivationScope scope) {
        List<DerivationParameter> parameterValues = new LinkedList<>();
        context.getSiteReport().getSupportedSignatureAndHashAlgorithms().stream()
                .filter(algo -> algo.suitedForSigningTls13Messages() || !scope.isTls13Test())
                .filter(algo -> SignatureAndHashAlgorithm.getImplemented().contains(algo))
                .forEach(algo -> parameterValues.add(new SigAndHashDerivation(algo)));
        return parameterValues;
    }

    private List<DerivationParameter> getServerTestAlgorithms() {
        //TLS-Scanner has no probe for this yet
        throw new UnsupportedOperationException("SigAndHash derivation is currently not supported for server tests");
    }

    @Override
    public void applyToConfig(Config config, TestContext context) {
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
    public List<ConditionalConstraint> getDefaultConditionalConstraints(DerivationScope scope) {
        List<ConditionalConstraint> condConstraints = new LinkedList<>();

        if (ConstraintHelper.pssSigAlgoModeled(scope) && ConstraintHelper.rsaPkMightNotSufficeForPss(scope)) {
            condConstraints.add(getMustNotBePSSWithShortRSAKeyConstraint());
        }

        if (ConstraintHelper.multipleCertPublicKeyTypesModeled(scope) || ConstraintHelper.multipleSigAlgorithmRequiredKeyTypesModeled(scope)) {
            condConstraints.add(getMustMatchPkOfCertificateConstraint());
        }
        
        if(ConstraintHelper.rsaPkBelow1024BitsModeled(scope) && ConstraintHelper.rsaShaAlgLongerThan256BitsModeled(scope)) {
            condConstraints.add(getMustNotBeRSA512withHashAbove256BitsConstraint());
        }

        if (!scope.isTls13Test()) {
            if (TestContext.getInstance().getSiteReport().getSupportedSignatureAndHashAlgorithms() == null && ConstraintHelper.multipleSigAlgorithmRequiredKeyTypesModeled(scope)) {
                condConstraints.add(getDefaultAlgorithmMustMatchCipherSuite());
            }

            if (ConstraintHelper.staticCipherSuiteModeled(scope)) {
                condConstraints.add(getMustBeNullForStaticCipherSuite());
            }

            if (ConstraintHelper.ephemeralCipherSuiteModeled(scope) && ConstraintHelper.nullSigHashModeled(scope)) {
                condConstraints.add(getMustNotBeNullForEphemeralCipherSuite());
            }

        } else {
            condConstraints.add(getHashSizeMustMatchEcdsaPkSizeConstraint());
        }
        return condConstraints;
    }

    private ConditionalConstraint getHashSizeMustMatchEcdsaPkSizeConstraint() {
        Set<DerivationType> requiredDerivations = new HashSet<>();
        requiredDerivations.add(DerivationType.CERTIFICATE);

        //TLS 1.3 specifies explicit curves for hash functions in ECDSA
        //e.g ecdsa_secp256r1_sha256
        return new ConditionalConstraint(requiredDerivations, ConstraintBuilder.constrain(getType().name(), DerivationType.CERTIFICATE.name()).by((SigAndHashDerivation sigAndHashDerivation, CertificateDerivation certificateDerivation) -> {
            if (sigAndHashDerivation.getSelectedValue() != null) {
                CertificateKeyPair certKeyPair = certificateDerivation.getSelectedValue();
                SignatureAlgorithm sigAlg = sigAndHashDerivation.getSelectedValue().getSignatureAlgorithm();
                HashAlgorithm hashAlgo = sigAndHashDerivation.getSelectedValue().getHashAlgorithm();

                if ((certKeyPair.getPublicKeyGroup() == NamedGroup.SECP256R1 && hashAlgo != HashAlgorithm.SHA256)
                        || (certKeyPair.getPublicKeyGroup() == NamedGroup.SECP384R1 && hashAlgo != HashAlgorithm.SHA384)
                        || (certKeyPair.getPublicKeyGroup() == NamedGroup.SECP521R1 && hashAlgo != HashAlgorithm.SHA512)) {
                    return false;
                }
            }
            return true;
        }));
    }

    private ConditionalConstraint getDefaultAlgorithmMustMatchCipherSuite() {
        Set<DerivationType> requiredDerivations = new HashSet<>();
        requiredDerivations.add(DerivationType.CIPHERSUITE);

        //see RFC 5246 - Section 7.4.1.4.1
        return new ConditionalConstraint(requiredDerivations, ConstraintBuilder.constrain(getType().name(), DerivationType.CIPHERSUITE.name()).by((SigAndHashDerivation sigAndHashDerivation, CipherSuiteDerivation cipherSuiteDerivation) -> {
            if (sigAndHashDerivation.getSelectedValue() != null) {
                CertificateKeyType requiredCertKeyType = AlgorithmResolver.getCertificateKeyType(cipherSuiteDerivation.getSelectedValue());
                
                switch (requiredCertKeyType) {
                    case RSA:
                        if (sigAndHashDerivation.getSelectedValue() != SignatureAndHashAlgorithm.RSA_SHA1) {
                            return false;
                        }
                        break;
                    case DSS:
                        if (sigAndHashDerivation.getSelectedValue() != SignatureAndHashAlgorithm.DSA_SHA1) {
                            return false;
                        }
                        break;
                    case ECDSA:
                        if (sigAndHashDerivation.getSelectedValue() != SignatureAndHashAlgorithm.ECDSA_SHA1) {
                            return false;
                        }
                        break;
                }
            }
            return true;
        }));
    }

    private ConditionalConstraint getMustBeNullForStaticCipherSuite() {
        Set<DerivationType> requiredDerivations = new HashSet<>();
        requiredDerivations.add(DerivationType.CIPHERSUITE);

        //see RFC 5246 - Section 7.4.1.4.1
        return new ConditionalConstraint(requiredDerivations, ConstraintBuilder.constrain(getType().name(), DerivationType.CIPHERSUITE.name()).by((SigAndHashDerivation sigAndHashDerivation, CipherSuiteDerivation cipherSuiteDerivation) -> {
            if (sigAndHashDerivation.getSelectedValue() != null && !cipherSuiteDerivation.getSelectedValue().isEphemeral()) {
                return false;
            }
            return true;
        }));
    }

    private ConditionalConstraint getMustNotBeNullForEphemeralCipherSuite() {
        Set<DerivationType> requiredDerivations = new HashSet<>();
        requiredDerivations.add(DerivationType.CIPHERSUITE);

        //see RFC 5246 - Section 7.4.1.4.1
        return new ConditionalConstraint(requiredDerivations, ConstraintBuilder.constrain(getType().name(), DerivationType.CIPHERSUITE.name()).by((SigAndHashDerivation sigAndHashDerivation, CipherSuiteDerivation cipherSuiteDerivation) -> {
            if (sigAndHashDerivation.getSelectedValue() == null && cipherSuiteDerivation.getSelectedValue().isEphemeral()) {
                return false;
            }
            return true;
        }));
    }

    private ConditionalConstraint getMustMatchPkOfCertificateConstraint() {
        Set<DerivationType> requiredDerivations = new HashSet<>();
        requiredDerivations.add(DerivationType.CERTIFICATE);

        return new ConditionalConstraint(requiredDerivations, ConstraintBuilder.constrain(getType().name(), DerivationType.CERTIFICATE.name()).by((SigAndHashDerivation sigAndHashDerivation, CertificateDerivation certificateDerivation) -> {
            if (sigAndHashDerivation.getSelectedValue() != null) {
                SignatureAlgorithm sigAlg = sigAndHashDerivation.getSelectedValue().getSignatureAlgorithm();
                switch (certificateDerivation.getSelectedValue().getCertPublicKeyType()) {
                    case ECDH:
                    case ECDSA:
                        if (sigAlg != SignatureAlgorithm.ECDSA) {
                            return false;
                        }
                        break;
                    case RSA:
                        if (!sigAlg.toString().contains("RSA")) {
                            return false;
                        }
                        break;
                    case DSS:
                        if (sigAlg != SignatureAlgorithm.DSA) {
                            return false;
                        }
                        break;
                    case GOST01:
                        if (sigAlg != SignatureAlgorithm.GOSTR34102001) {
                            return false;
                        }
                        break;
                    case GOST12:
                        if (sigAlg != SignatureAlgorithm.GOSTR34102012_256 && sigAlg != SignatureAlgorithm.GOSTR34102012_512) {
                            return false;
                        }
                        break;
                }
            }
            return true;
        }));
    }

    private ConditionalConstraint getMustNotBePSSWithShortRSAKeyConstraint() {
        Set<DerivationType> requiredDerivations = new HashSet<>();
        requiredDerivations.add(DerivationType.CERTIFICATE);

        //RSA 512 bit key does not suffice for PSS signature
        return new ConditionalConstraint(requiredDerivations, ConstraintBuilder.constrain(getType().name(), DerivationType.CERTIFICATE.name()).by((SigAndHashDerivation sigAndHashDerivation, CertificateDerivation certificateDerivation) -> {
            if (sigAndHashDerivation.getSelectedValue() != null) {
                SignatureAlgorithm sigAlg = sigAndHashDerivation.getSelectedValue().getSignatureAlgorithm();
                HashAlgorithm hashAlgo = sigAndHashDerivation.getSelectedValue().getHashAlgorithm();
                CertificateKeyPair selectedCertKeyPair = certificateDerivation.getSelectedValue();

                if (sigAlg.name().contains("PSS")) {
                    if (selectedCertKeyPair.getPublicKey().keySize() < 1024) {
                        return false;
                    } else if (hashAlgo == HashAlgorithm.SHA512 && selectedCertKeyPair.getPublicKey().keySize() < 2048) {
                        return false;
                    }
                }
            }
            return true;
        }));
    }
    
    private ConditionalConstraint getMustNotBeRSA512withHashAbove256BitsConstraint() {
        Set<DerivationType> requiredDerivations = new HashSet<>();
        requiredDerivations.add(DerivationType.CERTIFICATE);
        
        //RSA 512 bit key does not work with RSA_SHA[> 256] 
        return new ConditionalConstraint(requiredDerivations, ConstraintBuilder.constrain(getType().name(), DerivationType.CERTIFICATE.name()).by((SigAndHashDerivation sigAndHashDerivation, CertificateDerivation certificateDerivation) -> {
            if (sigAndHashDerivation.getSelectedValue() != null) {
                SignatureAlgorithm sigAlg = sigAndHashDerivation.getSelectedValue().getSignatureAlgorithm();
                HashAlgorithm hashAlgo = sigAndHashDerivation.getSelectedValue().getHashAlgorithm();
                CertificateKeyPair selectedCertKeyPair = certificateDerivation.getSelectedValue();
                
                if (selectedCertKeyPair.getPublicKey().keySize() < 1024 && sigAlg.name().contains("RSA") && isSHAHashLongerThan256Bits(hashAlgo)) {
                    return false;
                }
            }
            return true;
        }));
    }
    
    private boolean isSHAHashLongerThan256Bits(HashAlgorithm hashAlgo) {
        switch(hashAlgo) {
            case SHA384:
            case SHA512:
                return true;
            default:
               return false;
        }
    }

}
