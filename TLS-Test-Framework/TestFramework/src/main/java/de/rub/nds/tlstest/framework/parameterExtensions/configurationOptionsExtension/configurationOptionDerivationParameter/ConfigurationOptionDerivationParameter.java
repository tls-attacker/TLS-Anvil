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

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.TestSiteReport;
import de.rub.nds.tlstest.framework.model.DerivationScope;
import de.rub.nds.tlstest.framework.model.constraint.ConditionalConstraint;
import de.rub.nds.tlstest.framework.model.derivationParameter.DerivationParameter;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.ConfigOptionDerivationType;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.ConfigurationOptionValue;

import java.util.*;

public abstract class ConfigurationOptionDerivationParameter extends DerivationParameter<ConfigurationOptionValue> {
    public ConfigurationOptionDerivationParameter(ConfigOptionDerivationType type) {
        super(type, ConfigurationOptionValue.class);
    }

    @Override
    public void applyToConfig(Config config, TestContext context) {

    }

    @Override
    public List<DerivationParameter> getParameterValues(TestContext context, DerivationScope scope) {
        return getAllParameterValues(context);
    }

    public abstract List<DerivationParameter> getAllParameterValues(TestContext context);

    @Override
    public List<ConditionalConstraint> getDefaultConditionalConstraints(DerivationScope scope) {
        return getStaticConditionalConstraints();
    }

    /**
     * @return a list of conditional constraints independent of the the derivation scope (constraints applied to the precomputed IPM)
     */
    public List<ConditionalConstraint> getStaticConditionalConstraints() {
        return new LinkedList<>();
    }

    /**
     * Returns the value that results int the most feature-rich library build. It is required to create an upper boundary for
     * prefiltering test cases using the MethodCondition annotation.
     *
     * If the option does not touch any features at all 'ConfigurationOptionValue(false)' can be returned.
     *
     * @return the option value resulting int the most feature-rich library build
     */
    public abstract ConfigurationOptionValue getMaxFeatureValue();

    /**
     * Returns the implicit value that is chosen if a configuration option is not used. Must be overridden for non flag
     * values.
     *
     * @return the default value
     */
    public ConfigurationOptionValue getDefaultValue(){
        // Default (Override for non-flag values)
        return new ConfigurationOptionValue(false);
    }
}
