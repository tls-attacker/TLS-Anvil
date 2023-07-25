/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.model.derivationParameter;

import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlstest.framework.anvil.TlsAnvilConfig;
import de.rub.nds.tlstest.framework.anvil.TlsDerivationParameter;
import de.rub.nds.tlstest.framework.model.TlsParameterType;
import java.util.LinkedList;
import java.util.List;

public class GreaseCipherSuiteDerivation extends TlsDerivationParameter<CipherSuite> {

    public GreaseCipherSuiteDerivation() {
        super(TlsParameterType.GREASE_CIPHERSUITE, CipherSuite.class);
    }

    public GreaseCipherSuiteDerivation(CipherSuite selectedValue) {
        this();
        setSelectedValue(selectedValue);
    }

    @Override
    protected TlsDerivationParameter<CipherSuite> generateValue(CipherSuite selectedValue) {
        return new GreaseCipherSuiteDerivation(selectedValue);
    }

    @Override
    public List<DerivationParameter<TlsAnvilConfig, CipherSuite>> getParameterValues(
            DerivationScope derivationScope) {
        List<DerivationParameter<TlsAnvilConfig, CipherSuite>> parameterValues = new LinkedList<>();
        for (CipherSuite cipherSuite : CipherSuite.values()) {
            if (cipherSuite.isGrease()) {
                parameterValues.add(new GreaseCipherSuiteDerivation(cipherSuite));
            }
        }
        return parameterValues;
    }
}
