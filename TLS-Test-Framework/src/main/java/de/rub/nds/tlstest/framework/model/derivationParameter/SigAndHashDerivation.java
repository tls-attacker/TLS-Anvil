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
                return getClientTestDefaultAlgorithms();
            } else {
                return getClientTestAlgorithms(context, scope);
            }
        } else {
            return getServerTestAlgorithms();
        }
    }

    private List<DerivationParameter> getClientTestDefaultAlgorithms() {
        List<DerivationParameter> parameterValues = new LinkedList<>();
        //the applied algorithm depends on the chosen ciphersuite - see constraints
        //TLS 1.3 clients must send the extension if they expect a server cert
        parameterValues.add(new SigAndHashDerivation(SignatureAndHashAlgorithm.RSA_SHA1));
        parameterValues.add(new SigAndHashDerivation(SignatureAndHashAlgorithm.DSA_SHA1));
        parameterValues.add(new SigAndHashDerivation(SignatureAndHashAlgorithm.ECDSA_SHA1));

        return parameterValues;
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
        if (context.getConfig().getTestEndpointMode() == TestEndpointType.SERVER) {
            config.setDefaultClientSupportedSignatureAndHashAlgorithms(getSelectedValue());
        } else {
            config.setDefaultServerSupportedSignatureAndHashAlgorithms(getSelectedValue());
        }
    }

    @Override
    public List<ConditionalConstraint> getConditionalConstraints(DerivationScope scope) {
        List<ConditionalConstraint> condConstraints = new LinkedList<>();

        if (ConstraintHelper.pssSigAlgoModeled(scope)) {
            condConstraints.add(getMustNotBePSSWithShortRSAKeyConstraint());
        }

        if (ConstraintHelper.multipleCertPublicKeyTypesModeled(scope) && ConstraintHelper.multipleSigAlgorithmsModeled(scope)) {
            condConstraints.add(getMustMatchPkOfCertificateConstraint());
        }

        if (!scope.isTls13Test() && TestContext.getInstance().getSiteReport().getSupportedSignatureAndHashAlgorithms() == null) {
            condConstraints.add(getDefaultAlgorithmMustMatchCipherSuite());
        }

        if (scope.isTls13Test()) {
            condConstraints.add(getHashSizeMustMatchEcdsaPkSizeConstraint());
        }
        return condConstraints;
    }

    private ConditionalConstraint getHashSizeMustMatchEcdsaPkSizeConstraint() {
        Set<DerivationType> requiredDerivations = new HashSet<>();
        requiredDerivations.add(DerivationType.CERTIFICATE);

        //TLS 1.3 specifies explicit curves for hash functions in ECDSA
        //e.g ecdsa_secp256r1_sha256
        return new ConditionalConstraint(requiredDerivations, ConstraintBuilder.constrain(getType().name(), DerivationType.CERTIFICATE.name()).by((DerivationParameter sigHashAlgParam, DerivationParameter certParam) -> {
            SigAndHashDerivation sigHashAlg = (SigAndHashDerivation) sigHashAlgParam;
            CertificateDerivation cert = (CertificateDerivation) certParam;
            SignatureAlgorithm sigAlg = sigHashAlg.getSelectedValue().getSignatureAlgorithm();
            HashAlgorithm hashAlgo = sigHashAlg.getSelectedValue().getHashAlgorithm();

            CertificateKeyPair certKeyPair = cert.getSelectedValue();

            if ((certKeyPair.getPublicKeyGroup() == NamedGroup.SECP256R1 && hashAlgo != HashAlgorithm.SHA256)
                    || (certKeyPair.getPublicKeyGroup() == NamedGroup.SECP384R1 && hashAlgo != HashAlgorithm.SHA384)
                    || (certKeyPair.getPublicKeyGroup() == NamedGroup.SECP521R1 && hashAlgo != HashAlgorithm.SHA512)) {
                return false;
            }
            return true;
        }));
    }

    private ConditionalConstraint getDefaultAlgorithmMustMatchCipherSuite() {
        Set<DerivationType> requiredDerivations = new HashSet<>();
        requiredDerivations.add(DerivationType.CIPHERSUITE);

        //see RFC 5246 - Section 7.4.1.4.1
        return new ConditionalConstraint(requiredDerivations, ConstraintBuilder.constrain(getType().name(), DerivationType.CIPHERSUITE.name()).by((DerivationParameter sigHashAlgParam, DerivationParameter cipherSuiteParam) -> {
            SigAndHashDerivation sigHashAlg = (SigAndHashDerivation) sigHashAlgParam;
            CipherSuiteDerivation cipherSuite = (CipherSuiteDerivation) cipherSuiteParam;
            CertificateKeyType requiredCertKeyType = AlgorithmResolver.getCertificateKeyType(cipherSuite.getSelectedValue());
            switch (requiredCertKeyType) {
                case RSA:
                    if (sigHashAlg.getSelectedValue() != SignatureAndHashAlgorithm.RSA_SHA1) {
                        return false;
                    }
                    break;
                case DSS:
                    if (sigHashAlg.getSelectedValue() != SignatureAndHashAlgorithm.DSA_SHA1) {
                        return false;
                    }
                    break;
                case ECDSA:
                    if (sigHashAlg.getSelectedValue() != SignatureAndHashAlgorithm.ECDSA_SHA1) {
                        return false;
                    }
                    break;
            }
            return true;
        }));
    }

    private ConditionalConstraint getMustMatchPkOfCertificateConstraint() {
        Set<DerivationType> requiredDerivations = new HashSet<>();
        requiredDerivations.add(DerivationType.CERTIFICATE);

        //the certificate pk must be eligible for the chosen algorithm 
        return new ConditionalConstraint(requiredDerivations, ConstraintBuilder.constrain(getType().name(), DerivationType.CERTIFICATE.name()).by((DerivationParameter sigHashAlgParam, DerivationParameter certParam) -> {
            SigAndHashDerivation sigHashAlg = (SigAndHashDerivation) sigHashAlgParam;
            CertificateDerivation cert = (CertificateDerivation) certParam;
            SignatureAlgorithm sigAlg = sigHashAlg.getSelectedValue().getSignatureAlgorithm();
            switch (cert.getSelectedValue().getCertPublicKeyType()) {
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
            return true;
        }));
    }

    private ConditionalConstraint getMustNotBePSSWithShortRSAKeyConstraint() {
        Set<DerivationType> requiredDerivations = new HashSet<>();
        requiredDerivations.add(DerivationType.CERTIFICATE);

        //RSA 521 bit key does not suffice for PSS signature
        return new ConditionalConstraint(requiredDerivations, ConstraintBuilder.constrain(getType().name(), DerivationType.CERTIFICATE.name()).by((DerivationParameter sigHashAlgParam, DerivationParameter certParam) -> {
            SigAndHashDerivation sigHashAlg = (SigAndHashDerivation) sigHashAlgParam;
            CertificateDerivation cert = (CertificateDerivation) certParam;
            SignatureAlgorithm sigAlg = sigHashAlg.getSelectedValue().getSignatureAlgorithm();
            HashAlgorithm hashAlgo = sigHashAlg.getSelectedValue().getHashAlgorithm();

            if (sigAlg.name().contains("PSS")) {
                if (cert.getSelectedValue().getPublicKey().keySize() < 1024) {
                    return false;
                } else if (hashAlgo == HashAlgorithm.SHA512 && cert.getSelectedValue().getPublicKey().keySize() < 2048) {
                    return false;
                }
            }
            return true;
        }));
    }

}
