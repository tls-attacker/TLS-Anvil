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
import de.rub.nds.tlstest.framework.model.*;
import de.rub.nds.tlstest.framework.model.constraint.ConditionalConstraint;
import de.rub.nds.tlstest.framework.model.derivationParameter.DerivationParameter;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.buildManagement.ConfigurationOptionsBuildManager;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter.*;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionsConfig.ConfigurationOptionsConfig;

import de.rwth.swc.coffee4j.engine.constraint.HardConstraintCheckerFactory;
import de.rwth.swc.coffee4j.engine.generator.TestInputGroup;
import de.rwth.swc.coffee4j.engine.generator.ipog.Ipog;
import de.rwth.swc.coffee4j.engine.report.Report;
import de.rwth.swc.coffee4j.engine.report.ReportLevel;
import de.rwth.swc.coffee4j.model.Combination;
import de.rwth.swc.coffee4j.model.InputParameterModel;
import de.rwth.swc.coffee4j.engine.report.Reporter;

import de.rwth.swc.coffee4j.model.Parameter;
import de.rwth.swc.coffee4j.model.Value;
import de.rwth.swc.coffee4j.model.converter.IndexBasedModelConverter;
import de.rwth.swc.coffee4j.model.converter.ModelConverter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.*;
import java.util.function.Supplier;

/**
 * The DerivationCategoryManager responsible for the ConfigOptionsDerivationType. It also contains the configured
 * ConfigurationOptionsConfig and knows the required ConfigurationOptionsBuildManager.
 */
public class ConfigurationOptionsDerivationManager implements DerivationCategoryManager {
    private static ConfigurationOptionsDerivationManager instance = null;
    private static final Logger LOGGER = LogManager.getLogger();
    private ConfigurationOptionsConfig config;
    private List<List<ConfigurationOptionDerivationParameter>> compoundSetupList;

    public static synchronized ConfigurationOptionsDerivationManager getInstance() {
        if (ConfigurationOptionsDerivationManager.instance == null) {
            ConfigurationOptionsDerivationManager.instance = new ConfigurationOptionsDerivationManager();
        }
        return ConfigurationOptionsDerivationManager.instance;
    }

    private ConfigurationOptionsDerivationManager(){
        config = null;
        compoundSetupList = null;
    }

    @Override
    public DerivationParameter getDerivationParameterInstance(DerivationType type) {
        if(!(type instanceof ConfigOptionDerivationType)){
            throw new IllegalArgumentException("This manager can only handle ConfigOptionDerivationType but type '"+type+"' was passed.");
        }
        ConfigOptionDerivationType basicType = (ConfigOptionDerivationType) type;
        switch(basicType) {
            case ConfigurationOptionCompoundParameter:
                if(compoundSetupList == null){
                    throw new IllegalStateException("Cannot get ConfigurationOptionCompoundParameter before ConfigurationOptionsConfig was initialized.");
                }
                return new ConfigurationOptionCompoundParameter(compoundSetupList);
            case DisablePsk:
                return new DisablePskDerivation();
            case SeedingMethod:
                return new SeedingMethodDerivation();
            case EnableNistEcOptimizations:
                return new EnableNistEcOptimizationsDerivation();
            case DisableSse2:
                return new DisableSse2Derivation();
            case DisableBinaryEllipticCurves:
                return new DisableBinaryEllipticCurvesDerivation();
            case DisableMultiblock:
                return new DisableMultiblockDerivation();
            case EnableCompression:
                return new EnableCompressionDerivation();

            case DisableAfalgEngine:
                return new DisableAfalgEngineDerivation();
            case EnableEntropyGatheringDaemon:
                return new EnableEntropyGatheringDaemonDerivation();
            case DisableRdrand:
                return new DisableRdrandDerivation();
            case DisableCertificateTransparency:
                return new DisableCertificateTransparencyDerivation();
            case DisableNextProtocolNegotiationExtension:
                return new DisableNextProtocolNegotiationExtensionDerivation();
            case DisableOcspSupport:
                return new DisableOcspSupportDerivation();
            case EnableWeakSslCiphers:
                return new EnableWeakSslCiphersDerivation();
            case EnableMd2:
                return new EnableMd2Derivation();
            case EnableRc5:
                return new EnableRc5Derivation();
            case DisableAssemblerCode:
                return new DisableAssemblerCodeDerivation();

            case DisablePadlockEngine:
                return new DisablePadlockEngineDerivation();
            case DisablePosixIo:
                return new DisablePosixIoDerivation();
            case DisableExtensionForIpAddressesAndAsIdentifiers:
                return new DisableExtensionForIpAddressesAndAsIdentifiersDerivation();
            case DisableSrpCiphersuites:
                return new DisableSrpCiphersuitesDerivation();
            case EnableDevelopmentFlags:
                return new EnableDevelopmentFlagsDerivation();
            case EnableMemoryDebuggingSupport:
                return new EnableMemoryDebuggingSupportDerivation();
            case DisableErrorStrings:
                return new DisableErrorStringsDerivation();

            default:
                LOGGER.error("Derivation Type {} not implemented", type);
                throw new UnsupportedOperationException("Derivation Type not implemented");
        }
    }

    @Override
    public List<DerivationType> getDerivationsOfModel(DerivationScope derivationScope, ModelType baseModel) {
        if(config == null){
            throw new IllegalStateException("No ConfigurationOptionsConfig was set so far. Register it before calling this method.");
        }
        return new LinkedList<>(Arrays.asList(ConfigOptionDerivationType.ConfigurationOptionCompoundParameter));
        //return new LinkedList<>(config.getEnabledConfigOptionDerivations());
    }

    @Override
    public List<DerivationType> getAllDerivations() {
        return new LinkedList<>(Arrays.asList(ConfigOptionDerivationType.ConfigurationOptionCompoundParameter));
        //return new LinkedList<>(config.getEnabledConfigOptionDerivations());
    }

    public List<ConfigOptionDerivationType> getAllActivatedCOTypes() {
        return new LinkedList<>(config.getEnabledConfigOptionDerivations());
    }

    public List<DerivationType> getDerivationsOfModel(ModelType baseModel) {
        return getDerivationsOfModel(null, baseModel);
    }

    public void initializeConfigOptionsConfig(ConfigurationOptionsConfig optionsConfig){
        config = optionsConfig;
        initCompoundParameterSetup();
    }

    public ConfigurationOptionsConfig getConfigurationOptionsConfig(){
        return config;
    }

    public ConfigurationOptionsBuildManager getConfigurationOptionsBuildManager(){
        if(config == null){
            throw new IllegalStateException("No ConfigurationOptionsConfig was set so far. Register it before calling this method.");
        }
        return config.getBuildManager();
    }
    public class LoggerReporter implements Reporter{
        @Override
        public void report(ReportLevel level, Report report) {
            LOGGER.warn("Generation Reporter ({}): {}", level.toString(), report);
        }

        @Override
        public void report(ReportLevel level, Supplier<Report> reportSupplier) {
            LOGGER.warn("Generation Reporter ({}): {}", level.toString(), reportSupplier.get());
        }
    }

    private void initCompoundParameterSetup(){
        compoundSetupList = new LinkedList<>();
        int strength = TestContext.getInstance().getConfig().getStrength();

        // -- Create the IPM of coffee4j
        InputParameterModel.Builder builder = InputParameterModel.inputParameterModel("configuration-options-model");
        builder = builder.strength(strength);
        for(ConfigOptionDerivationType coType : config.getEnabledConfigOptionDerivations()){
            ConfigurationOptionDerivationParameter coDerivationParameter = (ConfigurationOptionDerivationParameter)getDerivationParameterInstance(coType);
            List<DerivationParameter> derivationParameterValues = coDerivationParameter.getAllParameterValues(TestContext.getInstance());
            // - Add values
            List<Value> values = new LinkedList<>();
            for(int idx = 0; idx < derivationParameterValues.size(); idx++){
                values.add(new Value(idx, derivationParameterValues.get(idx)));
            }
            builder = builder.parameter(new Parameter(coType.name(), values));
            // - Add constraints
            List<ConditionalConstraint> constraints = coDerivationParameter.getStaticConditionalConstraints();
            for(ConditionalConstraint condConstraint : constraints){
                boolean allRequiredParametersAvailable = condConstraint.getRequiredDerivations().stream().allMatch(reqDerivation -> config.getEnabledConfigOptionDerivations().contains(reqDerivation));
                if(allRequiredParametersAvailable){
                    builder = builder.exclusionConstraint(condConstraint.getConstraint());
                }
            }
        }
        InputParameterModel ipm = builder.build();
        // -- Convert the IPM to a model the IPOG algorithm can use.
        final ModelConverter converter = new IndexBasedModelConverter(ipm);
        // -- Create the combinations for combinatorial testing in the converted model.
        Ipog ipog = new Ipog(new HardConstraintCheckerFactory());
        Set<Supplier<TestInputGroup>> suppliers = ipog.generate(converter.getConvertedModel(), new LoggerReporter());

        TestInputGroup testInputGroup = null;
        for(Supplier<TestInputGroup> s : suppliers){
            TestInputGroup group = s.get();
            if(group.getIdentifier() == "Positive IpogAlgorithm Tests"){
                testInputGroup = group;
                break;
            }
        }
        if(testInputGroup == null){
            throw new RuntimeException("Configuration option combination could not be created.");
        }

        // -- Convert the computed combinations back to the model of the IPM and collect the derivation parameter combinations
        for(int[] testInput : testInputGroup.getTestInputs()){
            Combination convertedCombination = converter.convertCombination(testInput);
            List<ConfigurationOptionDerivationParameter> parameterCombinationList = new LinkedList<>();
            for (Value value : convertedCombination.getParameterValueMap().values()){
                if(!(value.get() instanceof ConfigurationOptionDerivationParameter)){
                    throw new RuntimeException("Value is no configuration option derivation parameter. This should never happen...");
                }
                ConfigurationOptionDerivationParameter codParameter = (ConfigurationOptionDerivationParameter)value.get();
                parameterCombinationList.add(codParameter);
            }
            // Sort after type for consistent order (not necessary)
            parameterCombinationList.sort(Comparator.comparing(e -> e.getType().toString()));
            compoundSetupList.add(Collections.unmodifiableList(parameterCombinationList));
        }

        compoundSetupList = Collections.unmodifiableList(compoundSetupList);

        LOGGER.debug("Testing configuration options with default combinations:\n{}", compoundSetupList);
    }

}



























//