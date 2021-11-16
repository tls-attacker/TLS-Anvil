package de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension;

import de.rub.nds.tlstest.framework.model.ParameterExtension;

import java.nio.file.Path;

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
    public boolean load() {
        // TODO
        return false;
    }

    @Override
    public boolean unload() {
        // TODO
        return false;
    }

    public void configureConfigPath(Path configPath){
        //TODO
    }

    @Override
    public String getIdentifier() {
        return "ConfigurationOptionsExtension";
    }
}
