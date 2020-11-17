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
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.model.DerivationScope;
import de.rub.nds.tlstest.framework.model.DerivationType;
import de.rub.nds.tlstest.framework.model.derivationParameter.CipherSuiteDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.DerivationFactory;
import de.rub.nds.tlstest.framework.model.derivationParameter.DerivationParameter;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Analyzes modeled parameter values for the Coffee4J model.
 * 
 * Each Coffee4J constraint requires at least one parameter combination that
 * is forbidden under the constraint. This class provides methods used to
 * add constraints only if this condition is met.
 */
public class ConstraintHelper {
    
    public static boolean multipleBlocksizesModeled(DerivationScope scope) {
        CipherSuiteDerivation cipherSuiteDeriv = (CipherSuiteDerivation)DerivationFactory.getInstance(DerivationType.CIPHERSUITE);
        List<DerivationParameter> values = cipherSuiteDeriv.getConstrainedParameterValues(TestContext.getInstance(), scope);
        Set<Integer> blockLengths = new HashSet<>();
        for(DerivationParameter param : values) {
            blockLengths.add(AlgorithmResolver.getCipher((CipherSuite)param.getSelectedValue()).getBlocksize());
        }
        
        return blockLengths.size() > 1;
    }
    
    public static boolean unpaddedCipherSuitesModeled(DerivationScope scope) {
        CipherSuiteDerivation cipherSuiteDeriv = (CipherSuiteDerivation)DerivationFactory.getInstance(DerivationType.CIPHERSUITE);
        List<DerivationParameter> values = cipherSuiteDeriv.getConstrainedParameterValues(TestContext.getInstance(), scope);
        for(DerivationParameter param : values) {
            if(!AlgorithmResolver.getCipher((CipherSuite)param.getSelectedValue()).usesPadding()) {
                return true;
            }
        }
        
        return false;
    }
    
    public static boolean multipleMacSizesModeled(DerivationScope scope) {
        CipherSuiteDerivation cipherSuiteDeriv = (CipherSuiteDerivation)DerivationFactory.getInstance(DerivationType.CIPHERSUITE);
        List<DerivationParameter> values = cipherSuiteDeriv.getConstrainedParameterValues(TestContext.getInstance(), scope);
        Set<Integer> macLengths = new HashSet<>();
        for(DerivationParameter param : values) {
            int macLen = AlgorithmResolver.getMacAlgorithm(scope.getTargetVersion(), (CipherSuite)param.getSelectedValue()).getSize();
            if(macLen > 0) {
                macLengths.add(macLen);
            }
        }
        
        return macLengths.size() > 1;
    }
    
    public static boolean ecdhCipherSuiteModeled(DerivationScope scope) {
        CipherSuiteDerivation cipherSuiteDeriv = (CipherSuiteDerivation)DerivationFactory.getInstance(DerivationType.CIPHERSUITE);
        List<DerivationParameter> values = cipherSuiteDeriv.getConstrainedParameterValues(TestContext.getInstance(), scope);
        for(DerivationParameter param : values) {
            if(AlgorithmResolver.getKeyExchangeAlgorithm((CipherSuite)param.getSelectedValue()).isKeyExchangeEcdh()) {
                return true;
            }
        }
        
        return false;
    }
}
