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
import de.rub.nds.tlsattacker.core.constants.CertificateKeyType;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CipherType;
import de.rub.nds.tlsattacker.core.constants.HKDFAlgorithm;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SignatureAlgorithm;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.model.DerivationScope;
import de.rub.nds.tlstest.framework.model.DerivationType;
import de.rub.nds.tlstest.framework.model.derivationParameter.CertificateDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.CipherSuiteDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.DerivationFactory;
import de.rub.nds.tlstest.framework.model.derivationParameter.DerivationParameter;
import de.rub.nds.tlstest.framework.model.derivationParameter.SigAndHashDerivation;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Analyzes modeled parameter values for the Coffee4J model.
 *
 * Each Coffee4J constraint requires at least one parameter combination that is
 * forbidden under the constraint. This class provides methods used to add
 * constraints only if this condition is met.
 */
public class ConstraintHelper {

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
    
        
    public static boolean multipleSigAlgorithmsModeled(DerivationScope scope) {
        SigAndHashDerivation sigHashDeriv = (SigAndHashDerivation)DerivationFactory.getInstance(DerivationType.SIG_HASH_ALGORIHTM);
        List<DerivationParameter> values = sigHashDeriv.getConstrainedParameterValues(TestContext.getInstance(), scope);
        Set<SignatureAlgorithm> sigAlgos = new HashSet<>();
        for(DerivationParameter param : values) {
            sigAlgos.add(((SigAndHashDerivation)param).getSelectedValue().getSignatureAlgorithm());
        }
        return sigAlgos.size() > 1;
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
        List<DerivationParameter> values = sigHashDeriv.getConstrainedParameterValues(TestContext.getInstance(), scope);
        return values.stream().anyMatch(param -> ((SigAndHashDerivation)param).getSelectedValue().name().contains("PSS"));
    }
    
    //TODO: integrate into AlgorithmResolver?
    private static int getAuthTagLen(CipherSuite cipherSuite) {
        if (cipherSuite.name().contains("CCM_8")) {
            return 8;
        }
        return 16;
    }
}
