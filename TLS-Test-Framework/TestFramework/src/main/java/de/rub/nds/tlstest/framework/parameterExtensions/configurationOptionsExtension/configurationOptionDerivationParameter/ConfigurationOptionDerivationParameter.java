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
import de.rub.nds.tlstest.framework.TestSiteReport;
import de.rub.nds.tlstest.framework.model.DerivationContainer;
import de.rub.nds.tlstest.framework.model.derivationParameter.DerivationParameter;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.ConfigOptionDerivationType;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.ConfigurationOptionValue;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.ConfigurationOptionsDerivationManager;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public abstract class ConfigurationOptionDerivationParameter extends DerivationParameter<ConfigurationOptionValue> {
    public ConfigurationOptionDerivationParameter(ConfigOptionDerivationType type) {
        super(type, ConfigurationOptionValue.class);
    }

    @Override
    public void configureParameterDependencies(Config config, TestContext context, DerivationContainer container){
        // Use a shared flag to check if the ConfigurationOptions were already configured. They only need to be
        // configured once per container, however this method is called multiple times.
        final String SETUP_DONE = "CONFIGURATION_OPTION_SETUP_DONE";
        Map<String, Object> sharedData = container.getSharedData();
        if(sharedData.containsKey(SETUP_DONE)){
            if(!(sharedData.get(SETUP_DONE) instanceof Boolean)){
                throw new IllegalStateException(
                        String.format("The shared data of the DerivationContainer must not contain the key '%s' of" +
                                "non Boolean data type. Stop messing with it :P", SETUP_DONE));
            }
            Boolean setupAlreadyDone = (Boolean) sharedData.get(SETUP_DONE);
            if(setupAlreadyDone){
                return;
            }
        }

        Set<ConfigurationOptionDerivationParameter> configOptionDerivations = new HashSet<>();
        for(DerivationParameter derivation : container.getDerivationList()){
            if(derivation instanceof ConfigurationOptionDerivationParameter){
                ConfigurationOptionDerivationParameter configOptionDerivation = (ConfigurationOptionDerivationParameter) derivation;
                configOptionDerivations.add(configOptionDerivation);
            }
        }

        TestSiteReport report = ConfigurationOptionsDerivationManager.getInstance()
                .getConfigurationOptionsBuildManager()
                .configureOptionSetAndGetSiteReport(config, context, configOptionDerivations);

        container.setAssociatedSiteReport(report);

        sharedData.put(SETUP_DONE, Boolean.TRUE);
    }

    @Override
    public void applyToConfig(Config config, TestContext context) {

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
