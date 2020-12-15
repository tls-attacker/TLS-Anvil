package de.rub.nds.tlstest.framework.model.derivationParameter;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.model.DerivationScope;
import de.rub.nds.tlstest.framework.model.DerivationType;
import java.util.LinkedList;
import java.util.List;

public class IncludePaddingExtensionDerivation extends DerivationParameter<Boolean> {

    public IncludePaddingExtensionDerivation() {
        super(DerivationType.INCLUDE_PADDING_EXTENSION, Boolean.class);
    }
    public IncludePaddingExtensionDerivation(Boolean selectedValue) {
        this();
        setSelectedValue(selectedValue);
    }

    @Override
    public List<DerivationParameter> getParameterValues(TestContext context, DerivationScope scope) {
        List<DerivationParameter> parameterValues = new LinkedList<>();
        parameterValues.add(new IncludePaddingExtensionDerivation(true));
        parameterValues.add(new IncludePaddingExtensionDerivation(false));
        return parameterValues;
    }

    @Override
    public void applyToConfig(Config config, TestContext context) {
        config.setAddPaddingExtension(getSelectedValue());
    }

}
