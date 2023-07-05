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
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlstest.framework.anvil.TlsAnvilConfig;
import de.rub.nds.tlstest.framework.anvil.TlsDerivationParameter;
import de.rub.nds.tlstest.framework.model.TlsParameterType;
import java.util.LinkedList;
import java.util.List;

public class GreaseNamedGroupDerivation extends TlsDerivationParameter<NamedGroup> {

    public GreaseNamedGroupDerivation() {
        super(TlsParameterType.GREASE_NAMED_GROUP, NamedGroup.class);
    }

    public GreaseNamedGroupDerivation(NamedGroup selectedValue) {
        this();
        setSelectedValue(selectedValue);
    }

    @Override
    protected TlsDerivationParameter<NamedGroup> generateValue(NamedGroup selectedValue) {
        return new GreaseNamedGroupDerivation(selectedValue);
    }

    @Override
    public List<DerivationParameter<TlsAnvilConfig, NamedGroup>> getParameterValues(
            DerivationScope derivationScope) {
        List<DerivationParameter<TlsAnvilConfig, NamedGroup>> parameterValues = new LinkedList<>();
        for (NamedGroup group : NamedGroup.values()) {
            if (group.isGrease()) {
                parameterValues.add(new GreaseNamedGroupDerivation(group));
            }
        }
        return parameterValues;
    }
}
