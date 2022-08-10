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

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.function.Supplier;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.TestSiteReport;
import de.rub.nds.tlstest.framework.model.DerivationCategoryManager;
import de.rub.nds.tlstest.framework.model.DerivationScope;
import de.rub.nds.tlstest.framework.model.DerivationType;
import de.rub.nds.tlstest.framework.model.ModelType;
import de.rub.nds.tlstest.framework.model.constraint.ConditionalConstraint;
import de.rub.nds.tlstest.framework.model.derivationParameter.DerivationParameter;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.buildManagement.ConfigurationOptionsBuildManager;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter.ConfigurationOptionCompoundDerivation;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter.ConfigurationOptionDerivationParameter;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter.DisableAfalgEngineDerivation;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter.DisableAssemblerCodeDerivation;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter.DisableBinaryEllipticCurvesDerivation;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter.DisableCertificateTransparencyDerivation;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter.DisableErrorStringsDerivation;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter.DisableExtensionForIpAddressesAndAsIdentifiersDerivation;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter.DisableMultiblockDerivation;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter.DisableNextProtocolNegotiationExtensionDerivation;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter.DisableOcspSupportDerivation;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter.DisablePadlockEngineDerivation;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter.DisablePosixIoDerivation;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter.DisablePskDerivation;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter.DisableRdrandDerivation;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter.DisableSrpCiphersuitesDerivation;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter.DisableSse2Derivation;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter.EnableCompressionDerivation;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter.EnableDevelopmentFlagsDerivation;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter.EnableEntropyGatheringDaemonDerivation;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter.EnableMd2Derivation;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter.EnableMemoryDebuggingSupportDerivation;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter.EnableNistEcOptimizationsDerivation;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter.EnableRc5Derivation;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter.EnableWeakSslCiphersDerivation;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter.SeedingMethodDerivation;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionsConfig.ConfigurationOptionsConfig;
import de.rwth.swc.coffee4j.engine.constraint.HardConstraintCheckerFactory;
import de.rwth.swc.coffee4j.engine.generator.TestInputGroup;
import de.rwth.swc.coffee4j.engine.generator.ipog.Ipog;
import de.rwth.swc.coffee4j.engine.report.Report;
import de.rwth.swc.coffee4j.engine.report.ReportLevel;
import de.rwth.swc.coffee4j.engine.report.Reporter;
import de.rwth.swc.coffee4j.model.Combination;
import de.rwth.swc.coffee4j.model.InputParameterModel;
import de.rwth.swc.coffee4j.model.Parameter;
import de.rwth.swc.coffee4j.model.Value;
import de.rwth.swc.coffee4j.model.converter.IndexBasedModelConverter;
import de.rwth.swc.coffee4j.model.converter.ModelConverter;

/**
 * The DerivationCategoryManager responsible for the ConfigOptionsDerivationType. It also contains the configured
 * ConfigurationOptionsConfig and knows the required ConfigurationOptionsBuildManager.
 */
public class ConfigurationOptionsDerivationManager implements DerivationCategoryManager {
    private static ConfigurationOptionsDerivationManager instance = null;
    private static final Logger LOGGER = LogManager.getLogger();
    private ConfigurationOptionsConfig config;
    private List<List<ConfigurationOptionDerivationParameter>> compoundSetupList;
    private Map<List<ConfigurationOptionDerivationParameter>, TestSiteReport> compoundSetupToSiteReport;
    

    public static synchronized ConfigurationOptionsDerivationManager getInstance() {
        if (ConfigurationOptionsDerivationManager.instance == null) {
            ConfigurationOptionsDerivationManager.instance = new ConfigurationOptionsDerivationManager();
        }
        return ConfigurationOptionsDerivationManager.instance;
    }

    private ConfigurationOptionsDerivationManager(){
        config = null;
        compoundSetupList = null;
        compoundSetupToSiteReport = null;
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
                return new ConfigurationOptionCompoundDerivation(compoundSetupList);
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
        return new LinkedList<>(Collections.singletonList(ConfigOptionDerivationType.ConfigurationOptionCompoundParameter));
    }

    @Override
    public List<DerivationType> getAllDerivations() {
        return new LinkedList<>(Collections.singletonList(ConfigOptionDerivationType.ConfigurationOptionCompoundParameter));
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

    public Map<List<ConfigurationOptionDerivationParameter>, TestSiteReport> getCompoundSetupToSiteReport(){
        return compoundSetupToSiteReport;
    }

    public List<TestSiteReport> getAllCompondSiteReports(){
        return new ArrayList<TestSiteReport>(compoundSetupToSiteReport.values());
    }

    public static class LoggerReporter implements Reporter{
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
        int strength = config.getConfigOptionsIpmStrength();

        // -- Create the IPM of coffee4j
        InputParameterModel.Builder builder = InputParameterModel.inputParameterModel("configuration-options-ipm");
        builder.strength(strength);
        for(ConfigOptionDerivationType coType : config.getEnabledConfigOptionDerivations()){
            ConfigurationOptionDerivationParameter coDerivationParameter = (ConfigurationOptionDerivationParameter)getDerivationParameterInstance(coType);
            List<DerivationParameter> derivationParameterValues = coDerivationParameter.getAllParameterValues(TestContext.getInstance());
            // - Add values
            List<Value> values = new LinkedList<>();
            for(int idx = 0; idx < derivationParameterValues.size(); idx++){
                values.add(new Value(idx, derivationParameterValues.get(idx)));
            }
            builder.parameter(new Parameter(coType.name(), values));
            // - Add constraints
            List<ConditionalConstraint> constraints = coDerivationParameter.getStaticConditionalConstraints();
            for(ConditionalConstraint condConstraint : constraints){
                boolean allRequiredParametersAvailable = condConstraint.getRequiredDerivations().stream().allMatch(
                        reqDerivation -> (reqDerivation instanceof ConfigOptionDerivationType) && config.getEnabledConfigOptionDerivations().contains((ConfigOptionDerivationType)reqDerivation));


                if(allRequiredParametersAvailable){
                    builder.exclusionConstraint(condConstraint.getConstraint());
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

    public void preBuildAndValidateAndFilterSetups(){
        // List<List<ConfigurationOptionDerivationParameter>> compoundSetupList;
        LOGGER.info("== Precompute config options builds ==");
        int buildFailedSetupCount = 0;

        List<List<ConfigurationOptionDerivationParameter>> successfulSetups = new LinkedList<>();
        compoundSetupToSiteReport = new HashMap<List<ConfigurationOptionDerivationParameter>, TestSiteReport>();

        for(List<ConfigurationOptionDerivationParameter> setup : compoundSetupList){
            try {
                Set<ConfigurationOptionDerivationParameter> setupSet = new HashSet<>(setup);
                Config config = Config.createEmptyConfig();
                Callable<TestSiteReport> testSiteReportCallable =
                        getConfigurationOptionsBuildManager().configureOptionSetAndReturnGetSiteReportCallable(config, TestContext.getInstance(), setupSet);
                TestSiteReport siteReport = testSiteReportCallable.call();

                compoundSetupToSiteReport.put(setup, siteReport);
                successfulSetups.add(setup);
            }
            catch(Exception e){
                LOGGER.error("Exception occurred while pre-building container for setup with options {}. Exception: ", setup, e);
                buildFailedSetupCount += 1;
            }
        }

        compoundSetupList = successfulSetups;
        if(buildFailedSetupCount > 0){
            LOGGER.warn("{} builds failed. Continuing with reduced setup (see below). Due to the reduced option set the " +
                    "configured test strength cannot be guaranteed. Consider stopping and reconfiguring the tests or adding" +
                    "constraints to prevent invalid combinations. " +
                    "Reduced options set: {}",buildFailedSetupCount, compoundSetupList);
        }

    }

}
