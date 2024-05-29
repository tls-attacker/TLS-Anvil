/*
 *  TLS-Test-Framework - A framework for modeling TLS tests
 *
 *  Copyright 2020 Ruhr University Bochum and
 *  TÜV Informationstechnik GmbH
 *
 *  Licensed under Apache License 2.0
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

package de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter;

import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.ConfigOptionParameterType;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.ConfigurationOptionValue;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** Disables PSK cipher suites */
public class DisablePskDerivation extends ConfigurationOptionDerivationParameter {
    private static final Logger LOGGER = LogManager.getLogger();

    public DisablePskDerivation() {
        super(ConfigOptionParameterType.DISABLE_PSK);
    }

    public DisablePskDerivation(ConfigurationOptionValue selectedValue) {
        this();
        setSelectedValue(selectedValue);
    }

    @Override
    public ConfigurationOptionValue getMaxFeatureValue() {
        return new ConfigurationOptionValue(false);
    }

    @Override
    public void applyToConfig(Config config, DerivationScope derivationScope) {}

    @Override
    public List<DerivationParameter<Config, ConfigurationOptionValue>> getParameterValues(
            DerivationScope derivationScope) {
        List<DerivationParameter<Config, ConfigurationOptionValue>> parameterValues =
                new LinkedList<>();
        parameterValues.add(new DisablePskDerivation(new ConfigurationOptionValue(false)));
        parameterValues.add(new DisablePskDerivation(new ConfigurationOptionValue(true)));

        return parameterValues;
    }

    @Override
    protected DerivationParameter<Config, ConfigurationOptionValue> generateValue(
            ConfigurationOptionValue selectedValue) {
        return new DisablePskDerivation(selectedValue);
    }
}
