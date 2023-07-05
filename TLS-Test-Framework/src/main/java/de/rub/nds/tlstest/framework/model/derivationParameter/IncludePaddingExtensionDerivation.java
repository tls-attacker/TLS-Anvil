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
import de.rub.nds.tlstest.framework.anvil.TlsAnvilConfig;
import de.rub.nds.tlstest.framework.anvil.TlsDerivationParameter;
import de.rub.nds.tlstest.framework.model.TlsParameterType;
import java.util.LinkedList;
import java.util.List;

public class IncludePaddingExtensionDerivation extends TlsDerivationParameter<Boolean> {

    public IncludePaddingExtensionDerivation() {
        super(TlsParameterType.INCLUDE_PADDING_EXTENSION, Boolean.class);
    }

    public IncludePaddingExtensionDerivation(Boolean selectedValue) {
        this();
        setSelectedValue(selectedValue);
    }

    @Override
    public List<DerivationParameter<TlsAnvilConfig, Boolean>> getParameterValues(
            DerivationScope derivationScope) {
        List<DerivationParameter<TlsAnvilConfig, Boolean>> parameterValues = new LinkedList<>();
        parameterValues.add(new IncludePaddingExtensionDerivation(true));
        parameterValues.add(new IncludePaddingExtensionDerivation(false));
        return parameterValues;
    }

    @Override
    public void applyToConfig(TlsAnvilConfig config, DerivationScope derivationScope) {
        config.getTlsConfig().setAddPaddingExtension(getSelectedValue());
    }

    @Override
    protected TlsDerivationParameter<Boolean> generateValue(Boolean selectedValue) {
        return new IncludePaddingExtensionDerivation(selectedValue);
    }
}
