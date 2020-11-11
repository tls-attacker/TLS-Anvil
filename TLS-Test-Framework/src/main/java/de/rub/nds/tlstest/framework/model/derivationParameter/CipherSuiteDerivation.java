/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlstest.framework.model.derivationParameter;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.model.DerivationScope;
import de.rub.nds.tlstest.framework.model.DerivationType;
import java.util.LinkedList;
import java.util.List;

/**
 *
 * @author marcel
 */
public class CipherSuiteDerivation extends DerivationParameter<CipherSuite> {
    
    public CipherSuiteDerivation() {
        super(DerivationType.CIPHERSUITE);
    }
    
    public CipherSuiteDerivation(CipherSuite selectedValue) {
        this();
        setSelectedValue(selectedValue);
    }

    @Override
    public void applyToConfig(Config config, TestContext context) {
        config.setDefaultClientSupportedCiphersuites(getSelectedValue());
        config.setDefaultSelectedCipherSuite(getSelectedValue());
    }

    @Override
    public List<DerivationParameter> getParameterValues(TestContext context, DerivationScope scope) {
        List<DerivationParameter> parameterValues = new LinkedList<>();
        for (CipherSuite cipherSuite : context.getSiteReport().getCipherSuites()) {
            if(scope.getKeyExchangeRequirements().compatibleWithCiphersuite(cipherSuite)) {
                parameterValues.add(new CipherSuiteDerivation(cipherSuite));
            }
        }
        
        return parameterValues;
    }
    
}
