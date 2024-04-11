/*
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension;

import de.rub.nds.tlstest.framework.FeatureExtractionResult;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionsConfig.ConfigurationOptionsConfig;
import java.io.FileNotFoundException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * This parameter extension is used to add ConfigOptionsDerivationType DerivationParameter%s to the
 * IPM. The DerivationParameters were selected by a config file; Its path must be passed using a
 * String.
 */
public class ConfigurationOptionsExtension {

    private static final Logger LOGGER = LogManager.getLogger();

    private static ConfigurationOptionsExtension instance = null;
    private ConfigurationOptionsConfig config;

    public static synchronized ConfigurationOptionsExtension getInstance() {
        if (ConfigurationOptionsExtension.instance == null) {
            ConfigurationOptionsExtension.instance = new ConfigurationOptionsExtension();
        }
        return ConfigurationOptionsExtension.instance;
    }

    private ConfigurationOptionsExtension() {}

    public void load(Object initData) {
        if (!(initData instanceof String)) {
            throw new IllegalArgumentException(
                    "The ConfigurationOptionsExtension requires a String for initialization data.");
        }
        String configPathString = (String) initData;
        Path configPath = Paths.get(configPathString);
        if (Files.notExists(configPath)) {
            throw new IllegalArgumentException(
                    String.format(
                            "Illegal path was passed. No file at '%s' can be found.",
                            configPath.toAbsolutePath()));
        }
        try {
            config = new ConfigurationOptionsConfig(configPath);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
            throw new IllegalArgumentException(
                    String.format(
                            "The passed configuration options config file '%s' could not be found.",
                            configPath));
        }
        LOGGER.info(
                "Testing with configuration options: {}",
                config.getEnabledConfigOptionDerivations());

        ConfigurationOptionsDerivationManager.getInstance().initializeConfigOptionsConfig(config);
        config.getBuildManager().init();
        ConfigurationOptionsDerivationManager.getInstance().preBuildAndValidateAndFilterSetups();

        FeatureExtractionResult maxFeatureExtractionResult =
                config.getBuildManager().getMaximalFeatureSiteReport();
        TestContext.getInstance().setFeatureExtractionResult(maxFeatureExtractionResult);
    }
}
