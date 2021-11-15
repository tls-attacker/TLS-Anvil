package de.rub.nds.tlstest.framework.model.derivationParameter;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.model.DerivationScope;
import de.rub.nds.tlstest.framework.model.DerivationType;
import java.util.List;

/**
 *
 */
public class ExtensionDerivation extends DerivationParameter<ExtensionType> {
    
    public ExtensionDerivation() {
        super(BasicDerivationType.EXTENSION, ExtensionType.class);
    }
    
    public ExtensionDerivation(ExtensionType selectedValue) {
        this();
        setSelectedValue(selectedValue);
    }

    @Override
    public List<DerivationParameter> getParameterValues(TestContext context, DerivationScope scope) {
        //currently this is only used for explicitly listed (unrequested) extensions
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public void applyToConfig(Config config, TestContext context) {
        //currently this is only used for explicitly listed (unrequested) extensions
    }

}
