package de.rub.nds.tlstest.framework.model.derivationParameter;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.model.DerivationScope;
import de.rub.nds.tlstest.framework.model.DerivationType;
import java.util.LinkedList;
import java.util.List;

/**
 * Defines values for the optiona TLS 1.3 padding lengths
 */
public class AdditionalPaddingLengthDerivation extends DerivationParameter<Integer> {
    
    public AdditionalPaddingLengthDerivation() {
        super(DerivationType.ADDITIONAL_PADDING_LENGTH, Integer.class);
    }
    
    public AdditionalPaddingLengthDerivation(Integer selectedValue) {
        this();
        setSelectedValue(selectedValue);
    }

    @Override
    public List<DerivationParameter> getParameterValues(TestContext context, DerivationScope scope) {
        List<DerivationParameter> parameterValues = new LinkedList<>();
        parameterValues.add(new AdditionalPaddingLengthDerivation(5));
        parameterValues.add(new AdditionalPaddingLengthDerivation(100));
        parameterValues.add(new AdditionalPaddingLengthDerivation(1000));
        return parameterValues; 
    }

    @Override
    public void applyToConfig(Config config, TestContext context) {
        config.setDefaultAdditionalPadding(getSelectedValue());
    }

}
