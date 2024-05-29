package de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension;

import de.rub.nds.anvilcore.model.parameter.ParameterScope;

public class ConfigOptionParameterScope extends ParameterScope {
    public static ConfigOptionParameterScope DEFAULT = new ConfigOptionParameterScope();

    @Override
    public String getUniqueScopeIdentifier() {
        return "ConfigOptionParameter";
    }
}
