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

import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.TestSiteReport;
import de.rub.nds.tlstest.framework.model.*;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter.ConfigurationOptionDerivationParameter;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionsConfig.ConfigurationOptionsConfig;

import java.io.FileNotFoundException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * This parameter extension is used to add ConfigOptionsDerivationType DerivationParameter%s to the IPM. The DerivationParameters
 * were selected by a config file; Its path must be passed using a String.
 */
public class ConfigurationOptionsExtension implements ParameterExtension {

    private static ConfigurationOptionsExtension instance = null;
    private ConfigurationOptionsConfig config;

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
        try {
            config = new ConfigurationOptionsConfig(configPath);
        }
        catch (FileNotFoundException e) {
            e.printStackTrace();
            throw new IllegalArgumentException(String.format("The passed configuration options config file '%s' could not be found.",configPath));
        }

        ConfigurationOptionsDerivationManager.getInstance().setConfigOptionsConfig(config);
        DerivationManager.getInstance().registerCategoryManager(ConfigOptionDerivationType.class, ConfigurationOptionsDerivationManager.getInstance());

        TestSiteReport maxSiteReport = createMaximalSiteReport();
        TestContext.getInstance().setSiteReport(maxSiteReport);
    }

    private TestSiteReport createMaximalSiteReport(){
        List<DerivationType> derivationTypes = ConfigurationOptionsDerivationManager.getInstance().getDerivationsOfModel(ModelType.GENERIC);
        Set<ConfigurationOptionDerivationParameter> optionSet = new HashSet<>();
        for(DerivationType type : derivationTypes){
            ConfigurationOptionDerivationParameter configOptionDerivation
                    = (ConfigurationOptionDerivationParameter) ConfigurationOptionsDerivationManager.getInstance().getDerivationParameterInstance(type);
            configOptionDerivation.setSelectedValue(configOptionDerivation.getMaxFeatureValue());
            optionSet.add(configOptionDerivation);
        }

        TestSiteReport report = config.getBuildManager().createSiteReportFromOptionSet(optionSet);
        return report;
    }

    @Override
    public void unload() {
        DerivationManager.getInstance().unregisterCategoryManager(ConfigOptionDerivationType.class);
        ConfigurationOptionsDerivationManager.getInstance().setConfigOptionsConfig(null);
        config = null;
    }

    @Override
    public String getIdentifier() {
        return "ConfigurationOptionsExtension";
    }
}
