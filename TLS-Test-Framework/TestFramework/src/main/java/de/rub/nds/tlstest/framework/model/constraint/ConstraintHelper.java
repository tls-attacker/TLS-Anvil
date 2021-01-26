/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.model.constraint;

import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.certificate.CertificateKeyPair;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CertificateKeyType;
import de.rub.nds.tlsattacker.core.constants.CipherType;
import de.rub.nds.tlsattacker.core.constants.HKDFAlgorithm;
import de.rub.nds.tlsattacker.core.constants.HashAlgorithm;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SignatureAlgorithm;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.crypto.keys.CustomDSAPrivateKey;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.model.DerivationScope;
import de.rub.nds.tlstest.framework.model.DerivationType;
import de.rub.nds.tlstest.framework.model.derivationParameter.CertificateDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.CipherSuiteDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.DerivationFactory;
import de.rub.nds.tlstest.framework.model.derivationParameter.DerivationParameter;
import de.rub.nds.tlstest.framework.model.derivationParameter.SigAndHashDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.SignatureBitmaskDerivation;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Analyzes modeled parameter values for the Coffee4J model.
 *
 * Each Coffee4J constraint requires at least one parameter combination that is
 * forbidden under the constraint. This class provides methods used to add
 * constraints only if this condition is met.
 */
public class ConstraintHelper {
    
    private static final Logger LOGGER = LogManager.getLogger();
    
    public static boolean staticEcdhCipherSuiteModeled(DerivationScope scope) {
        CipherSuiteDerivation cipherSuiteDeriv = (CipherSuiteDerivation) DerivationFactory.getInstance(DerivationType.CIPHERSUITE);
        List<DerivationParameter> values = cipherSuiteDeriv.getConstrainedParameterValues(TestContext.getInstance(), scope);
        for (DerivationParameter param : values) {
            CipherSuite cipherSuite = (CipherSuite) param.getSelectedValue();
            if(!cipherSuite.isEphemeral() && AlgorithmResolver.getKeyExchangeAlgorithm(cipherSuite).isKeyExchangeEcdh()) {
                return true;
            }
        }
        return false;
    }

    public static boolean multipleBlocksizesModeled(DerivationScope scope) {
        CipherSuiteDerivation cipherSuiteDeriv = (CipherSuiteDerivation) DerivationFactory.getInstance(DerivationType.CIPHERSUITE);
        List<DerivationParameter> values = cipherSuiteDeriv.getConstrainedParameterValues(TestContext.getInstance(), scope);
        Set<Integer> blockLengths = new HashSet<>();
        for (DerivationParameter param : values) {
            blockLengths.add(AlgorithmResolver.getCipher((CipherSuite) param.getSelectedValue()).getBlocksize());
        }

        return blockLengths.size() > 1;
    }

    public static boolean unpaddedCipherSuitesModeled(DerivationScope scope) {
        CipherSuiteDerivation cipherSuiteDeriv = (CipherSuiteDerivation) DerivationFactory.getInstance(DerivationType.CIPHERSUITE);
        List<DerivationParameter> values = cipherSuiteDeriv.getConstrainedParameterValues(TestContext.getInstance(), scope);
        for (DerivationParameter param : values) {
            CipherSuite cipherSuite = (CipherSuite) param.getSelectedValue(); 
            if (!cipherSuite.isUsingPadding(scope.getTargetVersion()) || AlgorithmResolver.getCipherType(cipherSuite) == CipherType.AEAD) {
                return true;
            }
        }

        return false;
    }

    public static boolean multipleMacSizesModeled(DerivationScope scope) {
        CipherSuiteDerivation cipherSuiteDeriv = (CipherSuiteDerivation) DerivationFactory.getInstance(DerivationType.CIPHERSUITE);
        List<DerivationParameter> values = cipherSuiteDeriv.getConstrainedParameterValues(TestContext.getInstance(), scope);
        Set<Integer> macLengths = new HashSet<>();
        for (DerivationParameter param : values) {
            int macLen = AlgorithmResolver.getMacAlgorithm(scope.getTargetVersion(), (CipherSuite) param.getSelectedValue()).getSize();
            if (macLen > 0) {
                macLengths.add(macLen);
            }
        }

        return macLengths.size() > 1;
    }

    public static boolean ecdhCipherSuiteModeled(DerivationScope scope) {
        CipherSuiteDerivation cipherSuiteDeriv = (CipherSuiteDerivation) DerivationFactory.getInstance(DerivationType.CIPHERSUITE);
        List<DerivationParameter> values = cipherSuiteDeriv.getConstrainedParameterValues(TestContext.getInstance(), scope);
        for (DerivationParameter param : values) {
            if (scope.isTls13Test()) {
                return true;
            }
            if (AlgorithmResolver.getKeyExchangeAlgorithm((CipherSuite) param.getSelectedValue()).isKeyExchangeEcdh()) {
                return true;
            }
        }

        return false;
    }

    public static boolean nonEcdhCipherSuiteModeled(DerivationScope scope) {
        CipherSuiteDerivation cipherSuiteDeriv = (CipherSuiteDerivation) DerivationFactory.getInstance(DerivationType.CIPHERSUITE);
        List<DerivationParameter> values = cipherSuiteDeriv.getConstrainedParameterValues(TestContext.getInstance(), scope);
        for (DerivationParameter param : values) {
            if (!AlgorithmResolver.getKeyExchangeAlgorithm((CipherSuite) param.getSelectedValue()).isKeyExchangeEcdh()) {
                return true;
            }
        }

        return false;
    }

public static boolean multipleHkdfSizesModeled(DerivationScope scope) {
        CipherSuiteDerivation cipherSuiteDeriv = (CipherSuiteDerivation)DerivationFactory.getInstance(DerivationType.CIPHERSUITE);
        List<DerivationParameter> values = cipherSuiteDeriv.getConstrainedParameterValues(TestContext.getInstance(), scope);
        Set<HKDFAlgorithm> hkdfAlgos = new HashSet<>();
        for(DerivationParameter param : values) {
            CipherSuite selectedCipher = (CipherSuite)param.getSelectedValue();
            hkdfAlgos.add(AlgorithmResolver.getHKDFAlgorithm(selectedCipher));
        }
        
        return hkdfAlgos.size() > 1;
    }
    
    public static boolean multipleTagSizesModeled(DerivationScope scope) {
        CipherSuiteDerivation cipherSuiteDeriv = (CipherSuiteDerivation)DerivationFactory.getInstance(DerivationType.CIPHERSUITE);
        List<DerivationParameter> values = cipherSuiteDeriv.getConstrainedParameterValues(TestContext.getInstance(), scope);
        Set<Integer> tagLengths = new HashSet<>();
        for(DerivationParameter param : values) {
            CipherSuite selectedCipher = (CipherSuite)param.getSelectedValue();
            tagLengths.add(getAuthTagLen(selectedCipher));
        }
        
        return tagLengths.size() > 1;
    }
    
    public static boolean nullModeled(DerivationScope scope, DerivationType type) {
        return DerivationFactory.getInstance(type).getConstrainedParameterValues(TestContext.getInstance(), scope)
                .stream().anyMatch(parameterValue -> ((DerivationParameter)parameterValue).getSelectedValue() == null);
    }
    
        
    public static boolean multipleSigAlgorithmRequiredKeyTypesModeled(DerivationScope scope) {
        SigAndHashDerivation sigHashDeriv = (SigAndHashDerivation)DerivationFactory.getInstance(DerivationType.SIG_HASH_ALGORIHTM);
        List<DerivationParameter> values = sigHashDeriv.getConstrainedParameterValues(TestContext.getInstance(), scope);
        Set<CertificateKeyType> keyTypes = new HashSet<>();
        for(DerivationParameter param : values) {
            SignatureAlgorithm sigAlgorithm = ((SigAndHashDerivation)param).getSelectedValue().getSignatureAlgorithm();
            if(sigAlgorithm.name().contains("RSA")) {
                keyTypes.add(CertificateKeyType.RSA);
            } else if(sigAlgorithm == SignatureAlgorithm.ECDSA) {
                keyTypes.add(CertificateKeyType.ECDSA);
            } else if(sigAlgorithm == SignatureAlgorithm.GOSTR34102012_256 || sigAlgorithm == SignatureAlgorithm.GOSTR34102012_256) {
                keyTypes.add(CertificateKeyType.GOST12);
            } else if(sigAlgorithm == SignatureAlgorithm.GOSTR34102001) {
                keyTypes.add(CertificateKeyType.GOST01);
            } else if(sigAlgorithm == SignatureAlgorithm.DSA) {
                keyTypes.add(CertificateKeyType.DSS);
            } else if(sigAlgorithm == SignatureAlgorithm.ANONYMOUS) {
                //does not require a certificate
            } else {
                LOGGER.warn("SignatureAlgorithm " + sigAlgorithm + " was selected but should not be supported by TLS-Attacker");
            }
        }
        return keyTypes.size() > 1;
    }
    
    public static boolean multipleCertPublicKeyTypesModeled(DerivationScope scope) {
        CertificateDerivation certDeriv = (CertificateDerivation)DerivationFactory.getInstance(DerivationType.CERTIFICATE);
        List<DerivationParameter> values = certDeriv.getConstrainedParameterValues(TestContext.getInstance(), scope);
        Set<CertificateKeyType> certKeyTypes = new HashSet<>();
        for(DerivationParameter param : values) {
            certKeyTypes.add(((CertificateDerivation)param).getSelectedValue().getCertPublicKeyType());
        }
        return certKeyTypes.size() > 1;
    }
    
    public static boolean pssSigAlgoModeled(DerivationScope scope) {
        SigAndHashDerivation sigHashDeriv = (SigAndHashDerivation)DerivationFactory.getInstance(DerivationType.SIG_HASH_ALGORIHTM);
        List<DerivationParameter> algorithms = sigHashDeriv.getConstrainedParameterValues(TestContext.getInstance(), scope);
        return algorithms.stream().anyMatch(param -> ((SigAndHashDerivation)param).getSelectedValue().name().contains("PSS"));
    }
    
    public static boolean rsaPkMightNotSufficeForPss(DerivationScope scope) {
        SigAndHashDerivation sigHashDeriv = (SigAndHashDerivation)DerivationFactory.getInstance(DerivationType.SIG_HASH_ALGORIHTM);
        List<DerivationParameter> algorithms = sigHashDeriv.getConstrainedParameterValues(TestContext.getInstance(), scope);
        CertificateDerivation certDerivation = (CertificateDerivation)DerivationFactory.getInstance(DerivationType.CERTIFICATE);
        List<DerivationParameter> certificates = certDerivation.getConstrainedParameterValues(TestContext.getInstance(), scope);
        boolean pssWithSha512modeled = algorithms.stream().anyMatch(algorithm -> 
            (((SigAndHashDerivation)algorithm).getSelectedValue().getSignatureAlgorithm() == SignatureAlgorithm.RSA_PSS_PSS || ((SigAndHashDerivation)algorithm).getSelectedValue().getSignatureAlgorithm() == SignatureAlgorithm.RSA_PSS_RSAE)
                    && ((SigAndHashDerivation)algorithm).getSelectedValue().getHashAlgorithm() == HashAlgorithm.SHA512);
        
        boolean rsaCertWithKeyBelow1024bitModeled = certificates.stream().anyMatch(certificate -> ((CertificateDerivation)certificate).getSelectedValue().getCertPublicKeyType() == CertificateKeyType.RSA 
                && ((CertificateDerivation)certificate).getSelectedValue().getPublicKey().keySize() < 1024);
        boolean rsaCertWithKeyBelow2048bitModeled = certificates.stream().anyMatch(certificate -> ((CertificateDerivation)certificate).getSelectedValue().getCertPublicKeyType() == CertificateKeyType.RSA 
                && ((CertificateDerivation)certificate).getSelectedValue().getPublicKey().keySize() < 2048);
        if(rsaCertWithKeyBelow1024bitModeled || (rsaCertWithKeyBelow2048bitModeled && pssWithSha512modeled)) {
            return true;
        }
        return false;
    }
    
    public static boolean signatureLengthConstraintApplicable(DerivationScope scope) {
        CertificateDerivation certDeriv = (CertificateDerivation) DerivationFactory.getInstance(DerivationType.CERTIFICATE);
        SignatureBitmaskDerivation sigBitmaskDeriv = (SignatureBitmaskDerivation) DerivationFactory.getInstance(DerivationType.SIGNATURE_BITMASK);
        List<DerivationParameter> bytePositions = sigBitmaskDeriv.getConstrainedParameterValues(TestContext.getInstance(), scope);
        int maxBytePosition = (int)bytePositions.get(bytePositions.size() - 1).getSelectedValue();
        for(DerivationParameter certDerivationValue: certDeriv.getConstrainedParameterValues(TestContext.getInstance(), scope)) {
            CertificateKeyPair certKeyPair = (CertificateKeyPair) certDerivationValue.getSelectedValue();
            int signatureLength;
            switch(certKeyPair.getCertPublicKeyType()) {
                case RSA:
                    signatureLength = sigBitmaskDeriv.computeEstimatedSignatureSize(SignatureAlgorithm.RSA, certKeyPair.getPublicKey().keySize());
                    break;
                case ECDH:  
                case ECDSA:
                    signatureLength = sigBitmaskDeriv.computeEstimatedSignatureSize(SignatureAlgorithm.ECDSA, certKeyPair.getPublicKey().keySize());
                    break;
                case DSS:  
                    signatureLength = sigBitmaskDeriv.computeEstimatedSignatureSize(SignatureAlgorithm.DSA, ((CustomDSAPrivateKey)certKeyPair.getPrivateKey()).getParams().getQ().bitLength());
                    break;
                default:
                    throw new RuntimeException("Can not compute signature size for CertPublicKeyType " + certKeyPair.getCertPublicKeyType());
            }
            
            if(maxBytePosition >= SignatureBitmaskDerivation.computeSignatureSizeForCertKeyPair(certKeyPair)) {
                return true;
            }
        }
        
        return false;
    }
    
    //TODO: integrate into AlgorithmResolver?
    private static int getAuthTagLen(CipherSuite cipherSuite) {
        if (cipherSuite.name().contains("CCM_8")) {
            return 8;
        }
        return 16;
    }
}
