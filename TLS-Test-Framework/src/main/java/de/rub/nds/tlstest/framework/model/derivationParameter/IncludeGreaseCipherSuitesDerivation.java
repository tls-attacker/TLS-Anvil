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
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlstest.framework.anvil.TlsDerivationParameter;
import de.rub.nds.tlstest.framework.model.TlsParameterType;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

public class IncludeGreaseCipherSuitesDerivation extends TlsDerivationParameter<Boolean> {

    public IncludeGreaseCipherSuitesDerivation() {
        super(TlsParameterType.INCLUDE_GREASE_CIPHER_SUITES, Boolean.class);
    }

    public IncludeGreaseCipherSuitesDerivation(Boolean selectedValue) {
        this();
        setSelectedValue(selectedValue);
    }

    @Override
    public List<DerivationParameter<Config, Boolean>> getParameterValues(
            DerivationScope derivationScope) {
        List<DerivationParameter<Config, Boolean>> parameterValues = new LinkedList<>();
        parameterValues.add(new IncludeGreaseCipherSuitesDerivation(true));
        parameterValues.add(new IncludeGreaseCipherSuitesDerivation(false));
        return parameterValues;
    }

    @Override
    public void postProcessConfig(Config config, DerivationScope derivationScope) {
        if (getSelectedValue()) {
            Arrays.asList(CipherSuite.values()).stream()
                    .filter(cipherSuite -> cipherSuite.isGrease())
                    .forEach(
                            greaseCipher ->
                                    config.getDefaultClientSupportedCipherSuites()
                                            .add(greaseCipher));
        }
    }

    @Override
    protected TlsDerivationParameter<Boolean> generateValue(Boolean selectedValue) {
        return new IncludeGreaseCipherSuitesDerivation(selectedValue);
    }
}
