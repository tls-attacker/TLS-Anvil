/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * Copyright 2022 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.model.derivationParameter;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.model.DerivationScope;
import de.rub.nds.tlstest.framework.model.DerivationType;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;


public class IncludeGreaseCipherSuitesDerivation extends DerivationParameter<Boolean> {

    public IncludeGreaseCipherSuitesDerivation() {
        super(DerivationType.INCLUDE_GREASE_CIPHER_SUITES, Boolean.class);
    }
    public IncludeGreaseCipherSuitesDerivation(Boolean selectedValue) {
        this();
        setSelectedValue(selectedValue);
    }

    @Override
    public List<DerivationParameter> getParameterValues(TestContext context, DerivationScope scope) {
        List<DerivationParameter> parameterValues = new LinkedList<>();
        parameterValues.add(new IncludeGreaseCipherSuitesDerivation(true));
        parameterValues.add(new IncludeGreaseCipherSuitesDerivation(false));
        return parameterValues;
    }

    @Override
    public void applyToConfig(Config config, TestContext context) {
    }

    @Override
    public void postProcessConfig(Config config, TestContext context) {
        if(getSelectedValue()) {
           Arrays.asList(CipherSuite.values()).stream()
                .filter(cipherSuite -> cipherSuite.isGrease())
                .forEach(greaseCipher -> config.getDefaultClientSupportedCipherSuites().add(greaseCipher)); 
        }
    }
    

}
