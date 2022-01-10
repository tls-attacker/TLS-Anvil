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

import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.model.DerivationScope;
import de.rub.nds.tlstest.framework.model.derivationParameter.DerivationParameter;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.ConfigOptionDerivationType;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.ConfigurationOptionValue;

import java.util.LinkedList;
import java.util.List;

public class SeedingMethodDerivation extends ConfigurationOptionDerivationParameter{

    // All these seeding method types are tested (individually)
    public enum SeedingMethodType {
        OsEntropySource,
        GetRandom,
        DevRandom,
        //EntropyGeneratingDaemon, <- build failure
        CpuCommand;
        //None; <- execution fails
    }

    public SeedingMethodDerivation(){
        super(ConfigOptionDerivationType.SeedingMethod);
    }

    public SeedingMethodDerivation(ConfigurationOptionValue selectedValue) {
        this();
        setSelectedValue(selectedValue);
    }

    @Override
    public List<DerivationParameter> getParameterValues(TestContext context, DerivationScope scope) {
        List<DerivationParameter> parameterValues = new LinkedList<>();

        for(SeedingMethodType seedingMethodType : SeedingMethodType.values()){
            parameterValues.add(new SeedingMethodDerivation(new ConfigurationOptionValue(seedingMethodType.name())));
        }

        return parameterValues;
    }

    @Override
    public ConfigurationOptionValue getMaxFeatureValue() {
        return new ConfigurationOptionValue(SeedingMethodType.OsEntropySource.name());
    }
}
