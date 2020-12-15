package de.rub.nds.tlstest.framework.model.derivationParameter;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.model.DerivationScope;
import de.rub.nds.tlstest.framework.model.DerivationType;
import java.util.LinkedList;
import java.util.List;


public class IncludePSKExchangeModesExtensionDerivation extends DerivationParameter<Boolean> {

    public IncludePSKExchangeModesExtensionDerivation() {
        super(DerivationType.INCLUDE_PSK_EXCHANGE_MODES_EXTENSION, Boolean.class);
    }
    public IncludePSKExchangeModesExtensionDerivation(Boolean selectedValue) {
        this();
        setSelectedValue(selectedValue);
    }

    @Override
    public List<DerivationParameter> getParameterValues(TestContext context, DerivationScope scope) {
        List<DerivationParameter> parameterValues = new LinkedList<>();
        parameterValues.add(new IncludePSKExchangeModesExtensionDerivation(true));
        parameterValues.add(new IncludePSKExchangeModesExtensionDerivation(false));
        return parameterValues;
    }

    @Override
    public void applyToConfig(Config config, TestContext context) {
        config.setAddPSKKeyExchangeModesExtension(getSelectedValue());
    }

}
