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
        EntropyGeneratingDaemon, // <- build failure in OpenSSL without edg (also it seems, it does
        // not work in docker containers)
        CpuCommand, // <- fails (very) frequently
        None // <- cannot be used in environment. Therefore unused.
    }

    public SeedingMethodDerivation() {
        super(ConfigOptionDerivationType.SEEDING_METHOD);
    }

    public SeedingMethodDerivation(ConfigurationOptionValue selectedValue) {
        this();
        setSelectedValue(selectedValue);
    }

    @Override
    public List<DerivationParameter> getAllParameterValues(TestContext context) {
        List<DerivationParameter> parameterValues = new LinkedList<>();
        List<SeedingMethodType> seedingMethodsToAdd =
                new LinkedList<>(
                        Arrays.asList(
                                SeedingMethodType.OsEntropySource,
                                SeedingMethodType.GetRandom,
                                SeedingMethodType.DevRandom));

        // List<DerivationType> activatedCODerivations =
        // ConfigurationOptionsDerivationManager.getInstance().getDerivationsOfModel(scope,
        // scope.getBaseModel());
        // if(activatedCODerivations.contains(ConfigOptionDerivationType.ENABLE_ENTROPY_GATHERING_DAEMON)){
        // seedingMethodsToAdd.add(SeedingMethodType.EntropyGeneratingDaemon);
        // }
        // seedingMethodsToAdd.add(SeedingMethodType.CpuCommand);

        for (SeedingMethodType seedingMethodType : seedingMethodsToAdd) {
            parameterValues.add(
                    new SeedingMethodDerivation(
                            new ConfigurationOptionValue(seedingMethodType.name())));
        }

        return parameterValues;
    }

    @Override
    public List<ConditionalConstraint> getStaticConditionalConstraints() {
        List<ConditionalConstraint> condConstraints = new LinkedList<>();
        // condConstraints.add(getEntropyGeneratingDaemonEnabledConstraint());
        // condConstraints.add(getDisableAssemblerCodeConstraint());
        return condConstraints;
    }

    private ConditionalConstraint getEntropyGeneratingDaemonEnabledConstraint() {
        Set<DerivationType> requiredDerivations = new HashSet<>();
        requiredDerivations.add(ConfigOptionDerivationType.ENABLE_ENTROPY_GATHERING_DAEMON);

        return new ConditionalConstraint(
                requiredDerivations,
                ConstraintBuilder.constrain(
                                getType().toString(),
                                ConfigOptionDerivationType.ENABLE_ENTROPY_GATHERING_DAEMON.name())
                        .by(
                                (SeedingMethodDerivation seedingMethodDerivation,
                                        EnableEntropyGatheringDaemonDerivation
                                                enableEgdDerivation) -> {
                                    ConfigurationOptionValue selectedSeedingMethod =
                                            seedingMethodDerivation.getSelectedValue();
                                    ConfigurationOptionValue selectedEgdFlag =
                                            enableEgdDerivation.getSelectedValue();

                                    return !selectedSeedingMethod
                                                    .getOptionValues()
                                                    .get(0)
                                                    .equals(
                                                            SeedingMethodType
                                                                    .EntropyGeneratingDaemon.name())
                                            || selectedEgdFlag.isOptionSet();
                                }));
    }

    // Build fails (tested in OpenSSL 1.1.1) when run with no-asm and --with-rand-seeds=rdcpu
    private ConditionalConstraint getDisableAssemblerCodeConstraint() {
        Set<DerivationType> requiredDerivations = new HashSet<>();
        requiredDerivations.add(ConfigOptionDerivationType.DISABLE_ASSEMBLER_CODE);

        return new ConditionalConstraint(
                requiredDerivations,
                ConstraintBuilder.constrain(
                                getType().toString(),
                                ConfigOptionDerivationType.DISABLE_ASSEMBLER_CODE.name())
                        .by(
                                (SeedingMethodDerivation seedingMethodDerivation,
                                        DisableAssemblerCodeDerivation
                                                disableAssemblerCodeDerivation) -> {
                                    ConfigurationOptionValue selectedSeedingMethod =
                                            seedingMethodDerivation.getSelectedValue();
                                    ConfigurationOptionValue selectedAsmFlag =
                                            disableAssemblerCodeDerivation.getSelectedValue();

                                    return !selectedSeedingMethod
                                                    .getOptionValues()
                                                    .get(0)
                                                    .equals(SeedingMethodType.CpuCommand.name())
                                            || selectedAsmFlag.isOptionSet();
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
