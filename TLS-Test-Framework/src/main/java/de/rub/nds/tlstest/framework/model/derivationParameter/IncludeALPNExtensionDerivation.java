package de.rub.nds.tlstest.framework.model.derivationParameter;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.model.DerivationScope;
import de.rub.nds.tlstest.framework.model.DerivationType;
import java.util.LinkedList;
import java.util.List;

public class IncludeALPNExtensionDerivation extends DerivationParameter<Boolean> {
    
    public IncludeALPNExtensionDerivation() {
        super(DerivationType.INCLUDE_ALPN_EXTENSION, Boolean.class);
    }
    public IncludeALPNExtensionDerivation(Boolean selectedValue) {
        this();
        setSelectedValue(selectedValue);
    }

    @Override
    public List<DerivationParameter> getParameterValues(TestContext context, DerivationScope scope) {
        List<DerivationParameter> parameterValues = new LinkedList<>();
        parameterValues.add(new IncludeALPNExtensionDerivation(true));
        parameterValues.add(new IncludeALPNExtensionDerivation(false));
        return parameterValues;
    }

    @Override
    public void applyToConfig(Config config, TestContext context) {
        config.setAddAlpnExtension(getSelectedValue());
    }

}
