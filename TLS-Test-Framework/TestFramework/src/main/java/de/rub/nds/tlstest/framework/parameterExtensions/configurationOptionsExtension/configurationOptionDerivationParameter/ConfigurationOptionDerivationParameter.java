/**
 *  TLS-Test-Framework - A framework for modeling TLS tests
 *
 *  Copyright 2020 Ruhr University Bochum and
 *  TÜV Informationstechnik GmbH
 *
 *  Licensed under Apache License 2.0
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

package de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.model.DerivationContainer;
import de.rub.nds.tlstest.framework.model.derivationParameter.DerivationParameter;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.ConfigOptionDerivationType;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.ConfigurationOptionValue;

public abstract class ConfigurationOptionDerivationParameter extends DerivationParameter<ConfigurationOptionValue> {
    public ConfigurationOptionDerivationParameter(ConfigOptionDerivationType type) {
        super(type, ConfigurationOptionValue.class);
    }

    //@Override
    void configureParameterDependencies(Config config, TestContext context, DerivationContainer container){
        // TODO
    }

    /**
     * Returns the value that results int the most feature-rich library build. It is required to create an upper boundary for
     * prefiltering test cases using the MethodCondition annotation.
     *
     * If the option does not touch any features at all 'ConfigurationOptionValue(false)' can be returned.
     *
     * @returns the option value resulting int the most feature-rich library build
     */
    public abstract ConfigurationOptionValue getMaxFeatureValue();
}
