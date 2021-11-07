package de.rwth.swc.coffee4j.engine.characterization;

import de.rwth.swc.coffee4j.engine.TestModel;
import de.rwth.swc.coffee4j.engine.TestResult;
import de.rwth.swc.coffee4j.engine.constraint.ConstraintChecker;
import de.rwth.swc.coffee4j.engine.report.Reporter;
import de.rwth.swc.coffee4j.engine.util.IntArrayWrapper;
import de.rwth.swc.coffee4j.engine.util.Preconditions;

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static de.rwth.swc.coffee4j.engine.util.IntArrayWrapper.wrap;
import static de.rwth.swc.coffee4j.engine.util.PredicateUtil.not;

/**
 * A "helper" class for some fault characterization algorithms. It has been observed that many algorithms like AIFL and
 * BEN work by keeping an internal list of suspicious combinations. They then generate new test inputs if a criterion
 * is met and those test inputs are used to refine the suspicious set by removing all suspicious combinations appearing
 * in a successful test. The basic housekeeping work is done by this class so the algorithms can focus on the important
 * bits.
 * <p>
 * The class keeps two sets of suspicious combinations in memory: the current one, and one from last iteration. This
 * is needed to calculate differences. Additionally, the {@link FaultCharacterizationConfiguration} and all test results
 * are stored.
 */
public abstract class SuspiciousCombinationAlgorithm implements FaultCharacterizationAlgorithm {
    
    protected final FaultCharacterizationConfiguration configuration;
    
    protected final Map<IntArrayWrapper, TestResult> testResults = new HashMap<>();
    
    protected Set<IntArrayWrapper> previousSuspiciousCombinations = new HashSet<>();
    protected Set<IntArrayWrapper> suspiciousCombinations = new HashSet<>();
    
    protected SuspiciousCombinationAlgorithm(FaultCharacterizationConfiguration configuration) {
        this.configuration = Preconditions.notNull(configuration);
    }
    
    protected TestModel getModel() {
        return configuration.getTestModel();
    }
    
    protected ConstraintChecker getChecker() {
        return configuration.getChecker();
    }
    
    protected Reporter getReporter() {
        return configuration.getReporter();
    }
    
    /**
     * In the first iteration all relevant sub combinations of failed test inputs are calculated via the
     * {@link #getRelevantSubCombinations(int[])} method. In every iteration the relevant sub combinations of all
     * successful test inputs are then subtracted from the suspicious combinations. Earlier, the suspicious set of last
     * iteration was saved to {@link #previousSuspiciousCombinations}.
     * <p>
     * If the concrete algorithm now decides more test inputs should be generated
     * ({@link #shouldGenerateFurtherTestInputs()}), this is done via {@link #generateNextTestInputs}. Otherwise, an empty
     * list is returned.
     *
     * @param nextTestResults the results of either the initial test suite in the first iteration, or all test inputs
     *                        generated in the previous generation. Must not be {@code null} nor empty
     * @return the next set of test inputs for which the result is needed for fault characterization
     * @throws NullPointerException     if nextTestResults is {@code null}
     * @throws IllegalArgumentException if nextTestResults is empty
     */
    @Override
    public List<int[]> computeNextTestInputs(Map<int[], TestResult> nextTestResults) {
        Preconditions.notNull(nextTestResults);
        Preconditions.check(!nextTestResults.isEmpty());
        
        adjustSuspiciousSet(nextTestResults);
        addToTestResults(nextTestResults);
        if (shouldGenerateFurtherTestInputs()) {
            return convertNextTestInputs(nextTestResults);
        } else {
            return Collections.emptyList();
        }
    }
    
    private void adjustSuspiciousSet(Map<int[], TestResult> nextTestResults) {
        previousSuspiciousCombinations = suspiciousCombinations;
        suspiciousCombinations = new HashSet<>(previousSuspiciousCombinations);
        
        if (testResults.isEmpty()) {
            initializeSuspiciousSet(nextTestResults);
        }
        removeSuccessfulCombinationsFromSuspiciousSet(nextTestResults);
    }
    
    private void initializeSuspiciousSet(Map<int[], TestResult> nextTestResults) {
        for (Map.Entry<int[], TestResult> entry : nextTestResults.entrySet()) {
            if (entry.getValue().isUnsuccessful()) {
                suspiciousCombinations.addAll(getRelevantSubCombinations(entry.getKey()));
            }
        }
    }
    
    private void removeSuccessfulCombinationsFromSuspiciousSet(Map<int[], TestResult> nextTestResults) {
        for (Map.Entry<int[], TestResult> entry : nextTestResults.entrySet()) {
            if (entry.getValue().isSuccessful()) {
                suspiciousCombinations.removeAll(getRelevantSubCombinations(entry.getKey()));
            }
        }
    }
    
    private void addToTestResults(Map<int[], TestResult> nextTestResults) {
        for (Map.Entry<int[], TestResult> entry : nextTestResults.entrySet()) {
            testResults.put(wrap(entry.getKey()), entry.getValue());
        }
    }
    
    private List<int[]> convertNextTestInputs(Map<int[], TestResult> newTestResults) {
        return generateNextTestInputs(newTestResults).stream().filter(not(testResults::containsKey)).distinct().map(IntArrayWrapper::getArray).collect(Collectors.toList());
    }
    
    /**
     * Defined which sub-combinations of any given combination can be part of the suspicious set. For example, BEN
     * only works on all t-value-combinations while AIFL considers all possible sub-combinations.
     *
     * @param combination for which the relevant sub-combinations are needed
     * @return all sub-combination the concrete algorithm considers
     */
    protected abstract Set<IntArrayWrapper> getRelevantSubCombinations(int[] combination);
    
    /**
     * @return Whether further test inputs should be generated. If not, {@link #computeFailureInducingCombinations()}
     * will be called next
     */
    protected abstract boolean shouldGenerateFurtherTestInputs();
    
    /**
     * The concrete algorithm generates test for which it needs the result for better fault characterization. If no further
     * characterization is needed, an empty list should be returned.
     *
     * @param newTestResults the results from the test inputs generated in the last iteration of the initially generated
     *                       test inputs if in the first iteration
     * @return test inputs for which the result is needed
     */
    protected abstract List<IntArrayWrapper> generateNextTestInputs(Map<int[], TestResult> newTestResults);
}
