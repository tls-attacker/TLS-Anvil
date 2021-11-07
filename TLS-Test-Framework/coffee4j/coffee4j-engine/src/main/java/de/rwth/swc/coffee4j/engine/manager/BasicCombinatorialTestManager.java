package de.rwth.swc.coffee4j.engine.manager;

import de.rwth.swc.coffee4j.engine.TestModel;
import de.rwth.swc.coffee4j.engine.characterization.FaultCharacterizationAlgorithm;
import de.rwth.swc.coffee4j.engine.characterization.FaultCharacterizationAlgorithmFactory;
import de.rwth.swc.coffee4j.engine.characterization.FaultCharacterizationConfiguration;
import de.rwth.swc.coffee4j.engine.TestResult;
import de.rwth.swc.coffee4j.engine.conflict.*;
import de.rwth.swc.coffee4j.engine.generator.TestInputGroup;
import de.rwth.swc.coffee4j.engine.generator.TestInputGroupGenerator;
import de.rwth.swc.coffee4j.engine.report.GenerationReporter;
import de.rwth.swc.coffee4j.engine.report.Report;
import de.rwth.swc.coffee4j.engine.report.ReportLevel;
import de.rwth.swc.coffee4j.engine.util.IntArrayWrapper;
import de.rwth.swc.coffee4j.engine.util.Preconditions;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import static de.rwth.swc.coffee4j.engine.util.IntArrayWrapper.wrap;
import static de.rwth.swc.coffee4j.engine.util.IntArrayWrapper.wrapToSet;

/**
 * A very basic manager for combinatorial tests. It is basic in the sense that it does not support any form of test
 * result caching and/or parallel generation of test input groups.
 */
public class BasicCombinatorialTestManager implements CombinatorialTestManager {
    
    private static final GenerationReporter NO_OP_REPORTER = new GenerationReporter() {
        @Override
        public void report(ReportLevel level, Report report) {
            //empty as this is a noop reporter
        }
        
        @Override
        public void report(ReportLevel level, Supplier<Report> reportSupplier) {
            //empty as this is a noop reporter
        }
    };
    
    private final CombinatorialTestConfiguration configuration;
    
    private final TestModel model;
    
    private final List<SingleGroupGenerationManager> managers = new ArrayList<>();
    
    public BasicCombinatorialTestManager(CombinatorialTestConfiguration configuration,
                                         TestModel model) {
        this.configuration = Preconditions.notNull(configuration);
        this.model = Preconditions.notNull(model);
    }

    @Override
    public List<MissingInvalidTuple> checkConstraintsForConflicts() {
        final ConflictDetectionManager conflictDetectionManager = new ConflictDetectionManager(
                configuration.getConflictDetectionConfiguration(),
                model);

        return conflictDetectionManager.detectMissingInvalidTuples();
    }

    @Override
    public List<DiagnosisHittingSet> computeMinimalDiagnosisHittingSets(List<MissingInvalidTuple> missingInvalidTuples) {
        Preconditions.notNull(missingInvalidTuples);
        Preconditions.check(configuration.getConflictDetectionConfiguration().isConflictDiagnosisEnabled());

        final ReduceBasedDiagnosisHittingSetBuilder builder = new ReduceBasedDiagnosisHittingSetBuilder(model);

        return builder.computeMinimalDiagnosisHittingSets(missingInvalidTuples);
    }

    /**
     * Generates all test input groups given by the supplied {@link TestInputGroupGenerator}s. All test inputs are then
     * returned. During the generation, the method
     * {@link GenerationReporter#testInputGroupGenerated(TestInputGroup, TestInputGroupGenerator)} is called for each
     * generated {@link TestInputGroup}.
     *
     * @return all generated test inputs from all groups. They are returned in the exact order in which the
     * {@link TestInputGroupGenerator}s returned them inside {@link TestInputGroup}s.
     */
    @Override
    public List<int[]> generateInitialTests() {
        return configuration.getGenerators().stream()
                .map(this::generateManagers)
                .flatMap(Collection::stream)
                .map(this::registerManager)
                .map(SingleGroupGenerationManager::generateInitialTests)
                .flatMap(Collection::stream)
                .collect(Collectors.toList());
    }
    
    private Set<SingleGroupGenerationManager> generateManagers(TestInputGroupGenerator generator) {
        final GenerationReporter generationReporter = configuration.getGenerationReporter().orElse(NO_OP_REPORTER);
        
        return generator.generate(model, generationReporter).stream()
                .map(testInputGroupSupplier -> new SingleGroupGenerationManager(
                        testInputGroupSupplier,
                        generator,
                        configuration.getFaultCharacterizationAlgorithmFactory().orElse(null),
                        generationReporter))
                .collect(Collectors.toSet());
    }
    
    private SingleGroupGenerationManager registerManager(SingleGroupGenerationManager manager) {
        managers.add(manager);
        return manager;
    }
    
    /**
     * Returns all additional test inputs needed for all {@link TestInputGroup}s managed by this manager.
     * For each managed {@link TestInputGroup} the following flow is used:
     * 1. Check if the test input is contained in either the initial set of generated test inputs (first iteration) or
     * in the requested test inputs for fault characterization (in all other iterations)
     * 1.1 If that is not the input, return an empty list of additionally needed test inputs
     * 1.2 if that is the input, check whether fault characterization is enabled (factory is given, group has configuration,
     * a test input in the initial set failed)
     * 1.2.1 if FL is not enabled, the group is considered finished and will never return test inputs again
     * 1.2.2 else, new test inputs are generated by the fault characterization algorithm provided by the factory and returned
     * <p>
     * When necessary, the method called the necessary methods on a given reporter:
     * -{@link GenerationReporter#faultCharacterizationStarted(TestInputGroup, FaultCharacterizationAlgorithm)}
     * -{@link GenerationReporter#faultCharacterizationTestInputsGenerated(TestInputGroup, List)}
     * -{@link GenerationReporter#faultCharacterizationFinished(TestInputGroup, List)}
     * -{@link GenerationReporter#testInputGroupFinished(TestInputGroup)}
     *
     * @param testInput  the test inputs for which's result additional test inputs shall be generated
     * @param testResult whether the test input was successful and if not how the failure was caused
     * @return a combined list of test inputs generated by the fault characterization of each test input group
     */
    @Override
    public List<int[]> generateAdditionalTestInputsWithResult(int[] testInput, TestResult testResult) {
        final IntArrayWrapper wrappedTestInputs = wrap(testInput);
        
        return managers.stream().map(manager -> manager.generateAdditionalTestInputsWithResult(wrappedTestInputs, testResult)).flatMap(Collection::stream).collect(Collectors.toList());
    }
    
    private static final class SingleGroupGenerationManager {
        
        private final Supplier<TestInputGroup> testInputGroupSupplier;
        private final TestInputGroupGenerator testInputGroupGenerator;
        private final FaultCharacterizationAlgorithmFactory faultCharacterizationAlgorithmFactory;
        private final GenerationReporter reporter;
        
        private TestInputGroup testInputGroup;
        private FaultCharacterizationAlgorithm faultCharacterizationAlgorithm;
        private Set<IntArrayWrapper> missingTestInputs;
        private Map<int[], TestResult> testResults;
        
        private SingleGroupGenerationManager(Supplier<TestInputGroup> testInputGroupSupplier, TestInputGroupGenerator testInputGroupGenerator, FaultCharacterizationAlgorithmFactory faultCharacterizationAlgorithmFactory, GenerationReporter reporter) {
            this.testInputGroupSupplier = testInputGroupSupplier;
            this.testInputGroupGenerator = testInputGroupGenerator;
            this.faultCharacterizationAlgorithmFactory = faultCharacterizationAlgorithmFactory;
            this.reporter = reporter;
        }
        
        List<int[]> generateInitialTests() {
            testInputGroup = testInputGroupSupplier.get();
            reporter.testInputGroupGenerated(testInputGroup, testInputGroupGenerator);
            final List<int[]> testInputs = testInputGroup.getTestInputs();
            initializeNextMissingTestInputs(testInputs);
            return testInputs;
        }
        
        private void initializeNextMissingTestInputs(List<int[]> testInputs) {
            missingTestInputs = wrapToSet(testInputs);
            testResults = new HashMap<>();
        }
        
        List<int[]> generateAdditionalTestInputsWithResult(IntArrayWrapper combination, TestResult testResult) {
            if (missingTestInputs.contains(combination)) {
                missingTestInputs.remove(combination);
                testResults.put(combination.getArray(), testResult);
                
                if (missingTestInputs.isEmpty()) {
                    if (shouldUseFaultCharacterization()) {
                        return nextFaultCharacterizationIteration();
                    } else {
                        reporter.testInputGroupFinished(testInputGroup);
                    }
                }
            }
            
            return Collections.emptyList();
        }
        
        private boolean shouldUseFaultCharacterization() {
            return faultCharacterizationAlgorithm != null || (faultCharacterizationAlgorithmFactory != null && testInputGroup.getFaultCharacterizationConfiguration().isPresent() && testResultsContainAnyFailure());
        }
        
        private boolean testResultsContainAnyFailure() {
            return testResults.values().stream().anyMatch(TestResult::isUnsuccessful);
        }
        
        private List<int[]> nextFaultCharacterizationIteration() {
            initializeCharacterizationAlgorithmIfNotInitialized();
            final List<int[]> nextTestInputs = faultCharacterizationAlgorithm.computeNextTestInputs(new HashMap<>(testResults));
            testResults.clear();
            
            if (nextTestInputs.isEmpty()) {
                final List<int[]> failureInducingCombinations = faultCharacterizationAlgorithm.computeFailureInducingCombinations();
                reporter.faultCharacterizationFinished(testInputGroup, failureInducingCombinations);
                reporter.testInputGroupFinished(testInputGroup);
            } else {
                reporter.faultCharacterizationTestInputsGenerated(testInputGroup, nextTestInputs);
                missingTestInputs.addAll(wrapToSet(nextTestInputs));
            }
            
            return nextTestInputs;
        }
        
        private void initializeCharacterizationAlgorithmIfNotInitialized() {
            if (faultCharacterizationAlgorithm == null) {
                final FaultCharacterizationConfiguration configuration = testInputGroup.getFaultCharacterizationConfiguration().orElseThrow(() -> new IllegalArgumentException("Algorithm cannot be initialized without " + " a configuration"));
                faultCharacterizationAlgorithm = faultCharacterizationAlgorithmFactory.create(configuration);
                reporter.faultCharacterizationStarted(testInputGroup, faultCharacterizationAlgorithm);
            }
        }
    }
}
