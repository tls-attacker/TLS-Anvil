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
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlstest.framework.anvil.TlsDerivationParameter;
import de.rub.nds.tlstest.framework.model.TlsParameterType;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

/** */
public class IncludeGreaseNamedGroupsDerivation extends TlsDerivationParameter<Boolean> {

    public IncludeGreaseNamedGroupsDerivation() {
        super(TlsParameterType.INCLUDE_GREASE_NAMED_GROUPS, Boolean.class);
    }

    public IncludeGreaseNamedGroupsDerivation(Boolean selectedValue) {
        this();
        setSelectedValue(selectedValue);
    }

    @Override
    public List<DerivationParameter<Config, Boolean>> getParameterValues(
            AnvilTestTemplate anvilTestTemplate) {
        List<DerivationParameter<Config, Boolean>> parameterValues = new LinkedList<>();
        parameterValues.add(new IncludeGreaseNamedGroupsDerivation(true));
        parameterValues.add(new IncludeGreaseNamedGroupsDerivation(false));
        return parameterValues;
    }

    @Override
    public void applyToConfig(Config config, AnvilTestTemplate anvilTestTemplate) {}

    @Override
    public void postProcessConfig(Config config, AnvilTestTemplate anvilTestTemplate) {
        if (getSelectedValue()) {
            Arrays.asList(NamedGroup.values()).stream()
                    .filter(group -> group.isGrease())
                    .forEach(
                            greaseGroup ->
                                    config.getDefaultClientNamedGroups()
                                            .add(greaseGroup));
        }
    }

    @Override
    protected TlsDerivationParameter<Boolean> generateValue(Boolean selectedValue) {
        return new IncludeGreaseNamedGroupsDerivation(selectedValue);
    }
}
