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
import de.rub.nds.tlstest.framework.model.DerivationContainer;
import de.rub.nds.tlstest.framework.model.DerivationScope;
import de.rub.nds.tlstest.framework.model.DerivationType;
import de.rub.nds.tlstest.framework.model.derivationParameter.DerivationParameter;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.ConfigOptionDerivationType;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.ConfigurationOptionsDerivationManager;

import java.util.*;
import java.util.concurrent.Callable;

public class ConfigurationOptionCompoundParameter extends DerivationParameter<List<ConfigurationOptionDerivationParameter>> {

    private final List<List<ConfigurationOptionDerivationParameter>> configOptionsSetupsList;

    @SuppressWarnings("unchecked")
    public ConfigurationOptionCompoundParameter(List<List<ConfigurationOptionDerivationParameter>> setupsList){
        super(ConfigOptionDerivationType.ConfigurationOptionCompoundParameter, (Class<List<ConfigurationOptionDerivationParameter>>)(Object)List.class);
        configOptionsSetupsList = setupsList;
    }

    private ConfigurationOptionCompoundParameter(List<List<ConfigurationOptionDerivationParameter>> setupsList,
                                                 List<ConfigurationOptionDerivationParameter> selectedValue){
        this(setupsList);
        setSelectedValue(selectedValue);
    }

    @Override
    public List<DerivationParameter> getParameterValues(TestContext context, DerivationScope scope) {
        List<DerivationParameter> parameterValues = new LinkedList<>();

        Set<DerivationType> scopeLimitations = new HashSet<>(scope.getScopeLimits());
        for(List<ConfigurationOptionDerivationParameter> setup : this.configOptionsSetupsList){
            List<ConfigurationOptionDerivationParameter> constrainedSetupList = new LinkedList<>(setup);
            // Scope Limitations (Set respective parameters to their default value)
            for(int i = 0; i < constrainedSetupList.size(); i++){
                DerivationType type = constrainedSetupList.get(i).getType();
                if(scopeLimitations.contains(type)){
                    ConfigurationOptionDerivationParameter defaultParam =
                            (ConfigurationOptionDerivationParameter) ConfigurationOptionsDerivationManager.getInstance()
                                    .getDerivationParameterInstance(type);

                    defaultParam.setSelectedValue(defaultParam.getDefaultValue());
                    constrainedSetupList.set(i, defaultParam);
                }
            }
            parameterValues.add(new ConfigurationOptionCompoundParameter(this.configOptionsSetupsList, constrainedSetupList));
        }

        return parameterValues;
    }

    public <T extends ConfigurationOptionDerivationParameter> T getDerivation(Class<T> clazz) {
        for(ConfigurationOptionDerivationParameter coParam : getSelectedValue()) {
            if(clazz.equals(coParam.getClass())) {
                @SuppressWarnings("unchecked") // if statement already checks class
                T castedCOParam = (T)coParam;
                return (T)castedCOParam;
            }
        }
        return null;
    }

    @Override
    public void configureParameterDependencies(Config config, TestContext context, DerivationContainer container){
        Set<ConfigurationOptionDerivationParameter> configOptionDerivations = new HashSet<>(getSelectedValue());

        Callable<TestSiteReport> reportCallable = ConfigurationOptionsDerivationManager.getInstance()
                .getConfigurationOptionsBuildManager()
                .configureOptionSetAndReturnGetSiteReportCallable(config, context, configOptionDerivations);

        container.configureGetAssociatedSiteReportCallable(reportCallable);
    }

    @Override
    public void onContainerFinalized(DerivationContainer container) {
        super.onContainerFinalized(container);

        Set<ConfigurationOptionDerivationParameter> configOptionDerivations = new HashSet<>(getSelectedValue());
        ConfigurationOptionsDerivationManager.getInstance().getConfigurationOptionsBuildManager().onTestFinished(configOptionDerivations);
    }


    @Override
    public void applyToConfig(Config config, TestContext context) { }

}
