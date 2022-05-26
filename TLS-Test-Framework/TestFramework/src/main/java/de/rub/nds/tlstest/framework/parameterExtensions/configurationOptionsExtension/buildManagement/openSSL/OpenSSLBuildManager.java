/**
 *  TLS-Test-Framework - A framework for modeling TLS tests
 *
 *  Copyright 2020 Ruhr University Bochum and
 *  TÜV Informationstechnik GmbH
 *
 *  Licensed under Apache License 2.0
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

package de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.buildManagement.openSSL;

import de.rub.nds.tlstest.framework.model.DerivationType;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.*;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.buildManagement.docker.DockerBasedBuildManager;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter.ConfigurationOptionDerivationParameter;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionsConfig.*;

import java.util.*;
import java.util.List;

/**
 * The OpenSSLBuildManager is a ConfigurationOptionsBuildManager to build modern OpenSSL versions. It uses
 * the OpenSSLDockerFactory for build creations.
 */
public class OpenSSLBuildManager extends DockerBasedBuildManager {

    public OpenSSLBuildManager(ConfigurationOptionsConfig configurationOptionsConfig){
        super(configurationOptionsConfig, new OpenSSLDockerFactory(configurationOptionsConfig));
    }

    @Override
    protected String translateOptionValue(ConfigurationOptionDerivationParameter optionParameter, Map<ConfigOptionDerivationType,ConfigOptionValueTranslation> optionsToTranslationMap){
        ConfigurationOptionValue value = optionParameter.getSelectedValue();
        if(value == null){
            throw new IllegalArgumentException("Passed option parameter has no selected value yet.");
        }
        DerivationType derivationType = optionParameter.getType();
        if(!(derivationType instanceof ConfigOptionDerivationType)){
            throw new IllegalArgumentException("Passed derivation parameter is not of type ConfigOptionDerivationType.");
        }
        ConfigOptionDerivationType optionType = (ConfigOptionDerivationType) derivationType;

        if(!optionsToTranslationMap.containsKey(optionType)){
            throw new IllegalStateException("The ConfigurationOptionsConfig's translation map does not contain the passed type");
        }

        ConfigOptionValueTranslation translation = optionsToTranslationMap.get(optionType);

        if(translation instanceof FlagTranslation){
            FlagTranslation flagTranslation = (FlagTranslation) translation;
            if(!value.isFlag()){
                throw new IllegalStateException("The ConfigurationOptionsConfig's translation is a flag, but the ConfigurationOptionValue isn't. Value can't be translated.");
            }

            if(value.isOptionSet()){
                return flagTranslation.getDataIfSet();
            }
            else{
                return flagTranslation.getDataIfNotSet();
            }
        }
        else if(translation instanceof SingleValueOptionTranslation){
            SingleValueOptionTranslation singleValueTranslation = (SingleValueOptionTranslation) translation;
            if(value.isFlag()){
                throw new IllegalStateException("The ConfigurationOptionsConfig's translation has a value, but the ConfigurationOptionValue is a flag. Value can't be translated.");
            }
            List<String> optionValues = value.getOptionValues();
            if(optionValues.size() != 1){
                throw new IllegalStateException("The ConfigurationOptionsConfig's translation has a single value, but the ConfigurationOptionValue is not a single value. Value can't be translated.");
            }
            String optionValue = optionValues.get(0);

            String translatedName = singleValueTranslation.getIdentifier();
            String translatedValue = singleValueTranslation.getValueTranslation(optionValue);

            return String.format("%s=%s", translatedName, translatedValue);
        }
        else{
            throw new UnsupportedOperationException(String.format("The OpenSSLBuildManager does not support translations '%s'.", translation.getClass()));
        }
    }

}

