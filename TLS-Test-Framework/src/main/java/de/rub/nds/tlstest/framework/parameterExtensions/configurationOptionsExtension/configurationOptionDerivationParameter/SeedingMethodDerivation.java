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

import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.ConfigOptionParameterType;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.ConfigurationOptionValue;
import java.util.*;

public class SeedingMethodDerivation extends ConfigurationOptionDerivationParameter {

    // All these seeding method types are tested (individually)
    public enum SeedingMethodType {
        OS_ENTROPY_SOURCE,
        GET_RANDOM,
        DEV_RANDOM,
        ENTROPY_GENERATING_DAEMON, // <- build failure in OpenSSL without edg (also it seems, it
        // does
        // not work in docker containers)
        CPU_COMMAND, // <- fails (very) frequently
        NONE // <- cannot be used in environment. Therefore unused.
    }

    public SeedingMethodDerivation() {
        super(ConfigOptionParameterType.SEEDING_METHOD);
    }

    public SeedingMethodDerivation(ConfigurationOptionValue selectedValue) {
        this();
        setSelectedValue(selectedValue);
    }

    @Override
    public ConfigurationOptionValue getMaxFeatureValue() {
        return new ConfigurationOptionValue(SeedingMethodType.OS_ENTROPY_SOURCE.name());
    }

    @Override
    public ConfigurationOptionValue getDefaultValue() {
        return new ConfigurationOptionValue(SeedingMethodType.OS_ENTROPY_SOURCE.name());
    }

    @Override
    public void applyToConfig(Config config, DerivationScope derivationScope) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public List<DerivationParameter<Config, ConfigurationOptionValue>> getParameterValues(
            DerivationScope derivationScope) {
        List<DerivationParameter<Config, ConfigurationOptionValue>> parameterValues =
                new LinkedList<>();
        List<SeedingMethodType> seedingMethodsToAdd =
                new LinkedList<>(
                        Arrays.asList(
                                SeedingMethodType.OS_ENTROPY_SOURCE,
                                SeedingMethodType.GET_RANDOM,
                                SeedingMethodType.DEV_RANDOM));
        for (SeedingMethodType seedingMethodType : seedingMethodsToAdd) {
            parameterValues.add(
                    new SeedingMethodDerivation(
                            new ConfigurationOptionValue(seedingMethodType.name())));
        }

        return parameterValues;
    }

    @Override
    protected DerivationParameter<Config, ConfigurationOptionValue> generateValue(
            ConfigurationOptionValue selectedValue) {
        return new SeedingMethodDerivation(selectedValue);
    }
}
