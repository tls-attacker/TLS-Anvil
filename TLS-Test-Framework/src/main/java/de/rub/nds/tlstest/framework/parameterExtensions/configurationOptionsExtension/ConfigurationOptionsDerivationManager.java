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

import de.rub.nds.anvilcore.model.constraint.ConditionalConstraint;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.model.parameter.ParameterScope;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlstest.framework.FeatureExtractionResult;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.buildManagement.ConfigurationOptionsBuildManager;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.buildManagement.docker.DockerBasedBuildManager;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.buildManagement.docker.DockerTestContainer;
import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.configurationOptionDerivationParameter.ConfigurationOptionDerivationParameter;
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
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.function.Supplier;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * The DerivationCategoryManager responsible for the ConfigOptionsDerivationType. It also contains
 * the configured ConfigurationOptionsConfig and knows the required
 * ConfigurationOptionsBuildManager.
 */
public class ConfigurationOptionsDerivationManager {
    private static ConfigurationOptionsDerivationManager instance = null;
    private static final Logger LOGGER = LogManager.getLogger();
    private ConfigurationOptionsConfig config;
    private List<List<ConfigurationOptionDerivationParameter>> compoundSetupList;
    private Map<List<ConfigurationOptionDerivationParameter>, FeatureExtractionResult>
            compoundFeatureExtractionResult;

    private ExecutorService buildExecutor;

    public static synchronized ConfigurationOptionsDerivationManager getInstance() {
        if (ConfigurationOptionsDerivationManager.instance == null) {
            ConfigurationOptionsDerivationManager.instance =
                    new ConfigurationOptionsDerivationManager();
        }
        return ConfigurationOptionsDerivationManager.instance;
    }

    private ConfigurationOptionsDerivationManager() {
        config = null;
        compoundSetupList = null;
        compoundFeatureExtractionResult = null;
    }

    public List<ConfigOptionParameterType> getAllActivatedCOTypes() {
        return new LinkedList<>(config.getEnabledConfigOptionDerivations());
    }

    public void initializeConfigOptionsConfig(ConfigurationOptionsConfig optionsConfig) {
        config = optionsConfig;
        initCompoundParameterSetup();
    }

    public ConfigurationOptionsConfig getConfigurationOptionsConfig() {
        return config;
    }

    public ConfigurationOptionsBuildManager getConfigurationOptionsBuildManager() {
        if (config == null) {
            throw new IllegalStateException(
                    "No ConfigurationOptionsConfig was set so far. Register it before calling this method.");
        }
        return config.getBuildManager();
    }

    public Map<List<ConfigurationOptionDerivationParameter>, FeatureExtractionResult>
            getCompoundFeatureExtractionResult() {
        return compoundFeatureExtractionResult;
    }

    public List<FeatureExtractionResult> getAllCompondSiteReports() {
        return new ArrayList<FeatureExtractionResult>(compoundFeatureExtractionResult.values());
    }

    public static class LoggerReporter implements Reporter {
        @Override
        public void report(ReportLevel level, Report report) {
            LOGGER.warn("Generation Reporter ({}): {}", level.toString(), report);
        }

        @Override
        public void report(ReportLevel level, Supplier<Report> reportSupplier) {
            LOGGER.warn("Generation Reporter ({}): {}", level.toString(), reportSupplier.get());
        }
    }

    private void initCompoundParameterSetup() {
        compoundSetupList = new LinkedList<>();
        int strength = config.getConfigOptionsIpmStrength();

        // -- Create the IPM of coffee4j
        InputParameterModel.Builder builder =
                InputParameterModel.inputParameterModel("configuration-options-ipm");
        builder.strength(strength);
        for (ConfigOptionParameterType coType : config.getEnabledConfigOptionDerivations()) {
            ConfigurationOptionDerivationParameter coDerivationParameter =
                    (ConfigurationOptionDerivationParameter)
                            coType.getInstance(ParameterScope.NO_SCOPE);
            // DerivationScopes are bound to test templates but this selection happens idependently
            // of any test template so we use null
            List<DerivationParameter<Config, ConfigurationOptionValue>> derivationParameterValues =
                    coDerivationParameter.getParameterValues(null);
            // - Add values
            List<Value> values = new LinkedList<>();
            for (int idx = 0; idx < derivationParameterValues.size(); idx++) {
                values.add(new Value(idx, derivationParameterValues.get(idx)));
            }
            builder.parameter(new Parameter(coType.name(), values));
            // - Add constraints
            List<ConditionalConstraint> constraints =
                    coDerivationParameter.getDefaultConditionalConstraints(null);
            for (ConditionalConstraint condConstraint : constraints) {
                boolean allRequiredParametersAvailable =
                        condConstraint.getRequiredParameters().stream()
                                .allMatch(
                                        reqParameter ->
                                                (reqParameter.getParameterType()
                                                                instanceof
                                                                ConfigOptionParameterType)
                                                        && config.getEnabledConfigOptionDerivations()
                                                                .contains(
                                                                        (ConfigOptionParameterType)
                                                                                reqParameter
                                                                                        .getParameterType()));

                if (allRequiredParametersAvailable) {
                    builder.exclusionConstraint(condConstraint.getConstraint());
                }
            }
        }
        InputParameterModel ipm = builder.build();
        // -- Convert the IPM to a model the IPOG algorithm can use.
        final ModelConverter converter = new IndexBasedModelConverter(ipm);
        // -- Create the combinations for combinatorial testing in the converted model.
        Ipog ipog = new Ipog(new HardConstraintCheckerFactory());
        Set<Supplier<TestInputGroup>> suppliers =
                ipog.generate(converter.getConvertedModel(), new LoggerReporter());

        TestInputGroup testInputGroup = null;
        for (Supplier<TestInputGroup> s : suppliers) {
            TestInputGroup group = s.get();
            if (group.getIdentifier() == "Positive IpogAlgorithm Tests") {
                testInputGroup = group;
                break;
            }
        }
        if (testInputGroup == null) {
            throw new RuntimeException("Configuration option combination could not be created.");
        }

        // -- Convert the computed combinations back to the model of the IPM and collect the
        // derivation parameter combinations
        for (int[] testInput : testInputGroup.getTestInputs()) {
            Combination convertedCombination = converter.convertCombination(testInput);
            List<ConfigurationOptionDerivationParameter> parameterCombinationList =
                    new LinkedList<>();
            for (Value value : convertedCombination.getParameterValueMap().values()) {
                if (!(value.get() instanceof ConfigurationOptionDerivationParameter)) {
                    throw new RuntimeException(
                            "Value is no configuration option derivation parameter. This should never happen...");
                }
                ConfigurationOptionDerivationParameter codParameter =
                        (ConfigurationOptionDerivationParameter) value.get();
                parameterCombinationList.add(codParameter);
            }
            // Sort after type for consistent order (not necessary)
            parameterCombinationList.sort(
                    Comparator.comparing(
                            e -> e.getParameterIdentifier().getParameterType().toString()));
            compoundSetupList.add(Collections.unmodifiableList(parameterCombinationList));
        }

        compoundSetupList = Collections.unmodifiableList(compoundSetupList);

        LOGGER.info("Compiled {} configuration option combinations", compoundSetupList.size());
    }

    public void preBuildAndValidateAndFilterSetups() {

        LOGGER.info("== Precompute config options builds ==");
        int buildFailedSetupCount = 0;

        List<List<ConfigurationOptionDerivationParameter>> successfulSetups = new LinkedList<>();
        HashMap<
                        List<ConfigurationOptionDerivationParameter>,
                        Future<Callable<FeatureExtractionResult>>>
                compoundSetupToFuture =
                        new HashMap<
                                List<ConfigurationOptionDerivationParameter>,
                                Future<Callable<FeatureExtractionResult>>>();
        compoundFeatureExtractionResult =
                new HashMap<
                        List<ConfigurationOptionDerivationParameter>, FeatureExtractionResult>();
        buildExecutor = Executors.newFixedThreadPool(config.getMaxSimultaneousBuilds());

        // Create all builds (with multiple threads if configured)
        for (List<ConfigurationOptionDerivationParameter> setup : compoundSetupList) {
            Set<ConfigurationOptionDerivationParameter> setupSet = new HashSet<>(setup);
            Config conf = Config.createEmptyConfig();
            Future<Callable<FeatureExtractionResult>> testSiteReportCallableFuture =
                    getFeatureExtractionFuture(conf, TestContext.getInstance(), setupSet);
            compoundSetupToFuture.put(setup, testSiteReportCallableFuture);
        }

        // Wait until all builds are finished
        for (Map.Entry<
                        List<ConfigurationOptionDerivationParameter>,
                        Future<Callable<FeatureExtractionResult>>>
                setupToFuture : compoundSetupToFuture.entrySet()) {
            while (!setupToFuture.getValue().isDone()) {
                try {
                    Thread.sleep(500);
                } catch (InterruptedException e) {
                    LOGGER.error(e);
                }
            }
        }

        LOGGER.info("== Check builds and precompute site reports ==");

        // Create all site reports and check if the builds were successful
        for (Map.Entry<
                        List<ConfigurationOptionDerivationParameter>,
                        Future<Callable<FeatureExtractionResult>>>
                setupToFuture : compoundSetupToFuture.entrySet()) {
            try {
                FeatureExtractionResult featureExtractionResult =
                        setupToFuture.getValue().get().call();

                compoundFeatureExtractionResult.put(
                        setupToFuture.getKey(), featureExtractionResult);
                successfulSetups.add(setupToFuture.getKey());
            } catch (Exception e) {
                LOGGER.error(
                        "Exception occurred while pre-building container for setup with options {}. Exception: ",
                        setupToFuture.getKey(),
                        e);
                buildFailedSetupCount += 1;
            }
        }

        compoundSetupList = successfulSetups;
        if (buildFailedSetupCount > 0) {
            LOGGER.warn(
                    "{} builds failed. Continuing with reduced setup (see below). Due to the reduced option set the "
                            + "configured test strength cannot be guaranteed. Consider stopping and reconfiguring the tests or adding"
                            + "constraints to prevent invalid combinations. "
                            + "Reduced options set: {}",
                    buildFailedSetupCount,
                    compoundSetupList);
        }
    }

    private Future<Callable<FeatureExtractionResult>> getFeatureExtractionFuture(
            Config conf,
            TestContext context,
            Set<ConfigurationOptionDerivationParameter> setupSet) {
        return buildExecutor.submit(
                () -> {
                    ConfigurationOptionsBuildManager coBuildManager =
                            getConfigurationOptionsBuildManager();
                    String containerTag =
                            coBuildManager.preparePeerConnection(conf, context, setupSet);
                    DockerTestContainer testContainer =
                            ((DockerBasedBuildManager) coBuildManager)
                                    .getDockerTagToContainerInfoMap()
                                    .get(containerTag);
                    return new DockerBasedBuildManager.FeatureExtractionCallback(testContainer);
                });
    }

    public List<List<ConfigurationOptionDerivationParameter>> getCompoundSetupList() {
        return compoundSetupList;
    }
}
