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
import de.rub.nds.tlstest.framework.model.DerivationType;
import de.rub.nds.tlstest.framework.model.constraint.ConditionalConstraint;
import de.rub.nds.tlstest.framework.model.derivationParameter.DerivationParameter;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.ConfigOptionDerivationType;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.ConfigurationOptionValue;
import de.rwth.swc.coffee4j.model.constraints.ConstraintBuilder;

import java.util.*;

public class SeedingMethodDerivation extends ConfigurationOptionDerivationParameter {

    // All these seeding method types are tested (individually)
    public enum SeedingMethodType {
        OsEntropySource,
        GetRandom,
        DevRandom,
        EntropyGeneratingDaemon, // <- build failure in OpenSSL without edg (also it seems, it does not work in docker containers)
        CpuCommand,
        None // <- cannot be used in environment. Therefore unused.
    }

    public SeedingMethodDerivation(){
        super(ConfigOptionDerivationType.SeedingMethod);
    }

    public SeedingMethodDerivation(ConfigurationOptionValue selectedValue) {
        this();
        setSelectedValue(selectedValue);
    }

    @Override
    public List<DerivationParameter> getAllParameterValues(TestContext context) {
        List<DerivationParameter> parameterValues = new LinkedList<>();
        List<SeedingMethodType> seedingMethodsToAdd = new LinkedList<>(Arrays.asList(
                SeedingMethodType.OsEntropySource, SeedingMethodType.GetRandom,
                SeedingMethodType.DevRandom, SeedingMethodType.CpuCommand));

        //List<DerivationType> activatedCODerivations = ConfigurationOptionsDerivationManager.getInstance().getDerivationsOfModel(scope, scope.getBaseModel());
        //if(activatedCODerivations.contains(ConfigOptionDerivationType.EnableEntropyGatheringDaemon)){
        //seedingMethodsToAdd.add(SeedingMethodType.EntropyGeneratingDaemon);
        //}

        for(SeedingMethodType seedingMethodType : seedingMethodsToAdd){
            parameterValues.add(new SeedingMethodDerivation(new ConfigurationOptionValue(seedingMethodType.name())));
        }

        return parameterValues;
    }

    @Override
    public List<ConditionalConstraint> getStaticConditionalConstraints() {
        List<ConditionalConstraint> condConstraints = new LinkedList<>();
        condConstraints.add(getEntropyGeneratingDaemonEnabledConstraint());
        return condConstraints;
    }

    private ConditionalConstraint getEntropyGeneratingDaemonEnabledConstraint() {
        Set<DerivationType> requiredDerivations = new HashSet<>();
        requiredDerivations.add(ConfigOptionDerivationType.EnableEntropyGatheringDaemon);

        return new ConditionalConstraint(requiredDerivations, ConstraintBuilder.constrain(getType().toString(), ConfigOptionDerivationType.EnableEntropyGatheringDaemon.name())
            .by((SeedingMethodDerivation seedingMethodDerivation, EnableEntropyGatheringDaemonDerivation enableEgdDerivation) ->
            {
                ConfigurationOptionValue selectedSeedingMethod = seedingMethodDerivation.getSelectedValue();
                ConfigurationOptionValue selectedEgdFlag = enableEgdDerivation.getSelectedValue();

                return !selectedSeedingMethod.getOptionValues().get(0).equals(SeedingMethodType.EntropyGeneratingDaemon.name()) ||
                        selectedEgdFlag.isOptionSet();
            }));
    }

    @Override
    public ConfigurationOptionValue getMaxFeatureValue() {
        return new ConfigurationOptionValue(SeedingMethodType.OsEntropySource.name());
    }

    @Override
    public ConfigurationOptionValue getDefaultValue() {
        return new ConfigurationOptionValue(SeedingMethodType.OsEntropySource.name());
    }
}
