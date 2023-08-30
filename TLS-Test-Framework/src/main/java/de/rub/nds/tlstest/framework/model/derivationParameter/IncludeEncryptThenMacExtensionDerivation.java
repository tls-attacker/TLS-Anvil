/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.model.derivationParameter;

import de.rub.nds.anvilcore.model.AnvilTestTemplate;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlstest.framework.anvil.TlsDerivationParameter;
import de.rub.nds.tlstest.framework.model.TlsParameterType;
import java.util.LinkedList;
import java.util.List;

public class IncludeEncryptThenMacExtensionDerivation extends TlsDerivationParameter<Boolean> {

    public IncludeEncryptThenMacExtensionDerivation() {
        super(TlsParameterType.INCLUDE_ENCRYPT_THEN_MAC_EXTENSION, Boolean.class);
    }

    public IncludeEncryptThenMacExtensionDerivation(Boolean selectedValue) {
        this();
        setSelectedValue(selectedValue);
    }

    @Override
    public void applyToConfig(Config config, AnvilTestTemplate anvilTestTemplate) {
        config.setAddEncryptThenMacExtension(getSelectedValue());
    }

    @Override
    protected TlsDerivationParameter<Boolean> generateValue(Boolean selectedValue) {
        return new IncludeEncryptThenMacExtensionDerivation(selectedValue);
    }

    @Override
    public List<DerivationParameter<Config, Boolean>> getParameterValues(
            AnvilTestTemplate anvilTestTemplate) {
        List<DerivationParameter<Config, Boolean>> parameterValues = new LinkedList<>();
        parameterValues.add(new IncludeEncryptThenMacExtensionDerivation(true));
        parameterValues.add(new IncludeEncryptThenMacExtensionDerivation(false));
        return parameterValues;
    }
}
