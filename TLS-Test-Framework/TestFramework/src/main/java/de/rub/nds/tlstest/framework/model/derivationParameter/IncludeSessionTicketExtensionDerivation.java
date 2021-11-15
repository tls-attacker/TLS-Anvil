package de.rub.nds.tlstest.framework.model.derivationParameter;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.model.DerivationScope;
import de.rub.nds.tlstest.framework.model.DerivationType;
import java.util.LinkedList;
import java.util.List;

/**
 *
 */
public class IncludeSessionTicketExtensionDerivation extends DerivationParameter<Boolean> {

    public IncludeSessionTicketExtensionDerivation() {
        super(BasicDerivationType.INCLUDE_SESSION_TICKET_EXTENSION, Boolean.class);
    }
    public IncludeSessionTicketExtensionDerivation(Boolean selectedValue) {
        this();
        setSelectedValue(selectedValue);
    }

    @Override
    public List<DerivationParameter> getParameterValues(TestContext context, DerivationScope scope) {
        List<DerivationParameter> parameterValues = new LinkedList<>();
        parameterValues.add(new IncludeSessionTicketExtensionDerivation(true));
        parameterValues.add(new IncludeSessionTicketExtensionDerivation(false));
        return parameterValues;
    }

    @Override
    public void applyToConfig(Config config, TestContext context) {
        config.setAddSessionTicketTLSExtension(getSelectedValue());
    }
}
