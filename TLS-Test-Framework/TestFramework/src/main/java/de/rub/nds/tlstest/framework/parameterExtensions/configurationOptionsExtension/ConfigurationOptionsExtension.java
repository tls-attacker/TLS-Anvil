/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension;

import de.rub.nds.tlstest.framework.model.DerivationManager;
import de.rub.nds.tlstest.framework.model.ParameterExtension;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionsConfig.ConfigurationOptionsConfig;

import java.io.FileNotFoundException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * This parameter extension is used to add ConfigOptionsDerivationType DerivationParameter%s to the IPM. The DerivationParameters
 * were selected by a config file; Its path must be passed using a String.
 */
public class ConfigurationOptionsExtension implements ParameterExtension {

    private static ConfigurationOptionsExtension instance = null;

    public static synchronized ConfigurationOptionsExtension getInstance() {
        if (ConfigurationOptionsExtension.instance == null) {
            ConfigurationOptionsExtension.instance = new ConfigurationOptionsExtension();
        }
        return ConfigurationOptionsExtension.instance;
    }

    private ConfigurationOptionsExtension(){
    }

    @Override
    public void load(Object initData) {
        if(!(initData instanceof String)){
            throw new IllegalArgumentException("The ConfigurationOptionsExtension requires a String for initialization data.");
        }
        String configPathString = (String) initData;
        Path configPath = Paths.get(configPathString);
        if(Files.notExists(configPath)){
            throw new IllegalArgumentException(String.format("Illegal path was passed. No file at '%s' can be found.", configPath.toAbsolutePath().toString()));
        }
        ConfigurationOptionsConfig config;
        try {
            config = new ConfigurationOptionsConfig(configPath);
        }
        catch (FileNotFoundException e) {
            e.printStackTrace();
            throw new IllegalArgumentException("The passed configuration options config file could not be parsed.");
        }

        ConfigurationOptionsDerivationManager.getInstance().setConfigOptionsConfig(config);
        DerivationManager.getInstance().registerCategoryManager(ConfigOptionDerivationType.class, ConfigurationOptionsDerivationManager.getInstance());

        //TODO: Create maximal Site Report using the appropriate BuildManager

    }

    @Override
    public void unload() {
        // TODO
        return;
    }

    @Override
    public String getIdentifier() {
        return "ConfigurationOptionsExtension";
    }
}
