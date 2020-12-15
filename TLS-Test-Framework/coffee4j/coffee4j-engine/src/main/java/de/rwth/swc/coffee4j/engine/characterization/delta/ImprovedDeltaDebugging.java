package de.rwth.swc.coffee4j.engine.characterization.delta;

import de.rwth.swc.coffee4j.engine.TestModel;
import de.rwth.swc.coffee4j.engine.TestResult;
import de.rwth.swc.coffee4j.engine.characterization.FaultCharacterizationAlgorithm;
import de.rwth.swc.coffee4j.engine.characterization.FaultCharacterizationAlgorithmFactory;
import de.rwth.swc.coffee4j.engine.characterization.FaultCharacterizationConfiguration;
import de.rwth.swc.coffee4j.engine.util.IntArrayWrapper;
import de.rwth.swc.coffee4j.engine.util.Preconditions;
import it.unimi.dsi.fastutil.ints.IntOpenHashSet;
import it.unimi.dsi.fastutil.ints.IntSet;
import it.unimi.dsi.fastutil.objects.Object2BooleanMap;
import it.unimi.dsi.fastutil.objects.Object2BooleanOpenHashMap;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.IntStream;

import static de.rwth.swc.coffee4j.engine.util.CombinationUtil.NO_VALUE;
import static de.rwth.swc.coffee4j.engine.util.CombinationUtil.contains;
import static de.rwth.swc.coffee4j.engine.util.CombinationUtil.sameForAllGivenParameters;
import static de.rwth.swc.coffee4j.engine.util.IntArrayWrapper.wrap;
import static de.rwth.swc.coffee4j.engine.util.PredicateUtil.not;

/**
 * An implementation of the Improved Delta Debugging algorithm as described in "Improved Delta Debugging Based on
 * Combinatorial Testing".
 * Basically, the algorithm performs a binary search on failed test inputs to discover failure-inducing combinations.
 * This is done in two steps. The Isolation Algorithm computes one value in the test input which is responsible for
 * failure, while the RI algorithm uses this isolation algorithm to find complete failure-inducing combinations.
 * This implementation goes a bit further by allowing the discovery of failure-inducing combinations for multiple test
 * inputs. All failed test inputs are therefore searched test input by test input, except if failure-inducing combinations
 * found for previous test inputs already explanation a failure. Then it is assumed that no other combination is present in
 * the test input.
 * <p>
 * Important Information:
 * -Generates a very predictable amount of test inputs due to binary search
 * -Does not generate many test inputs per failure inducing combination
 * -Does not work well if two failure-inducing combinations are present in one failed test input or if failure-inducing
 * combinations overlap each other.
 * -Does not consider constraints
 */
public class ImprovedDeltaDebugging implements FaultCharacterizationAlgorithm {
    
    private State state = State.INITIALIZATION;
    
    private final TestModel testModel;
    
    private final Object2BooleanMap<IntArrayWrapper> coveringArray = new Object2BooleanOpenHashMap<>();
    
    private final List<int[]> failureInducingCombinations = new ArrayList<>();
    
    private int[] currentFailedTestInput = null;
    private int[] nextExpectedTestInput = null;
    
    private IntSet relatedParameters = null;
    private IntSet unrelatedParameters = null;
    private IntSet suspiciousParameters = null;
    private IntSet subParametersOne = null;
    private IntSet subParametersTwo = null;
    
    /**
     * Creates a new Improved Delta Debugging algorithm for the given configuration. The ConstraintsChecker is ignored.
     *
     * @param configuration the configuration for the algorithm
     */
    public ImprovedDeltaDebugging(FaultCharacterizationConfiguration configuration) {
        Preconditions.notNull(configuration);
        
        this.testModel = configuration.getTestModel();
    }
    
    /**
     * @return a factory always returning new instances of the Improved Delta Debugging algorithm
     */
    public static FaultCharacterizationAlgorithmFactory improvedDeltaDebugging() {
        return ImprovedDeltaDebugging::new;
    }
    
    @Override
    public List<int[]> computeNextTestInputs(Map<int[], TestResult> testResults) {
        assertAlgorithmInitialized();
        Preconditions.notNull(testResults);
        Preconditions.check(state == State.INITIALIZATION || containsExpectedTestInput(testResults));
        
        addToCoveringArray(testResults);
        
        do {
            computeNextTestInput();
        } while (nextExpectedTestInput != null && coveringArray.containsKey(wrap(nextExpectedTestInput)));
        
        return nextExpectedTestInput == null ? Collections.emptyList() : Collections.singletonList(nextExpectedTestInput);
    }
    
    private void assertAlgorithmInitialized() {
        if (testModel == null) {
            throw new IllegalStateException("The algorithm has not been initialized");
        }
    }
    
    private boolean containsExpectedTestInput(Map<int[], TestResult> testResults) {
        for (int[] testInput : testResults.keySet()) {
            if (Arrays.equals(testInput, nextExpectedTestInput)) {
                return true;
            }
        }
        
        return false;
    }
    
    private void addToCoveringArray(Map<int[], TestResult> testResults) {
        for (Map.Entry<int[], TestResult> testResult : testResults.entrySet()) {
            coveringArray.put(wrap(testResult.getKey()), testResult.getValue().isSuccessful());
        }
    }
    
    private void computeNextTestInput() {
        switch (state) {
            case INITIALIZATION:
                initializeNextFailedTestInput();
                break;
            case ISOLATION:
                continueIsolationWithNextTestResult();
                break;
            case CHECK:
                checkIfFurtherIsolationNeededWithTestResult();
                break;
            default:
                throw new IllegalStateException("No state set");
        }
    }
    
    private void initializeNextFailedTestInput() {
        relatedParameters = new IntOpenHashSet();
        final Optional<int[]> nextFailedTestInput = findNextUnexplainedFailedTestInput();
        
        if (nextFailedTestInput.isPresent()) {
            currentFailedTestInput = nextFailedTestInput.get();
            findNextSuspiciousSchemaAndInvokeIsolation();
        } else {
            nextExpectedTestInput = null;
        }
    }
    
    private Optional<int[]> findNextUnexplainedFailedTestInput() {
        return coveringArray.object2BooleanEntrySet().stream().filter(not(Object2BooleanMap.Entry::getBooleanValue)).map(Object2BooleanMap.Entry::getKey).map(IntArrayWrapper::getArray).filter(testInput -> failureInducingCombinations.stream().noneMatch(failureInducingCombination -> contains(testInput, failureInducingCombination))).findFirst();
    }
    
    private void findNextSuspiciousSchemaAndInvokeIsolation() {
        final Optional<int[]> nearestTestInput = findNearestPassedTestInput();
        suspiciousParameters = new IntOpenHashSet();
        if (nearestTestInput.isPresent()) {
            suspiciousParameters.addAll(calculateDifference(currentFailedTestInput, nearestTestInput.get()));
        } else {
            IntStream.range(0, currentFailedTestInput.length).filter(parameter -> !relatedParameters.contains(parameter)).forEach(suspiciousParameters::add);
        }
        isolateParameter();
    }
    
    private Optional<int[]> findNearestPassedTestInput() {
        return coveringArray.object2BooleanEntrySet().stream().filter(Object2BooleanMap.Entry::getBooleanValue).map(Object2BooleanMap.Entry::getKey).map(IntArrayWrapper::getArray).filter(testInput -> sameForAllGivenParameters(testInput, currentFailedTestInput, relatedParameters)).max(Comparator.comparingInt(this::similarityToFailedTestInput));
    }
    
    private int similarityToFailedTestInput(int[] testInput) {
        int numberOfSameParameters = 0;
        
        for (int parameter = 0; parameter < testInput.length; parameter++) {
            if (testInput[parameter] == currentFailedTestInput[parameter]) {
                numberOfSameParameters++;
            }
        }
        
        return numberOfSameParameters;
    }
    
    private IntSet calculateDifference(int[] first, int[] second) {
        final IntSet differentParameters = new IntOpenHashSet();
        
        for (int parameter = 0; parameter < first.length; parameter++) {
            if (first[parameter] != second[parameter]) {
                differentParameters.add(parameter);
            }
        }
        
        return differentParameters;
    }
    
    private void isolateParameter() {
        unrelatedParameters = new IntOpenHashSet();
        divideSuspiciousSchemaAndExecuteTestInput();
    }
    
    private void divideSuspiciousSchemaAndExecuteTestInput() {
        if (suspiciousParameters.size() == 1) {
            addIsolatedParameterToRelatedSchema();
        } else {
            divideSchemaIntoSubSchemas();
            makeIsolationTestInput();
        }
    }
    
    private void addIsolatedParameterToRelatedSchema() {
        relatedParameters.addAll(suspiciousParameters);
        makeTestInputForCheckWhetherFurtherIsolationIsNeeded();
    }
    
    private void makeTestInputForCheckWhetherFurtherIsolationIsNeeded() {
        nextExpectedTestInput = new int[currentFailedTestInput.length];
        
        for (int parameter = 0; parameter < nextExpectedTestInput.length; parameter++) {
            if (relatedParameters.contains(parameter)) {
                nextExpectedTestInput[parameter] = currentFailedTestInput[parameter];
            } else {
                final int otherValueIndex = (currentFailedTestInput[parameter] + 1) % testModel.getSizeOfParameter(parameter);
                nextExpectedTestInput[parameter] = otherValueIndex;
            }
        }
        
        state = State.CHECK;
    }
    
    private void divideSchemaIntoSubSchemas() {
        final int firstSubSchemaSize = suspiciousParameters.size() / 2;
        
        subParametersOne = new IntOpenHashSet(firstSubSchemaSize);
        subParametersTwo = new IntOpenHashSet(suspiciousParameters.size() - firstSubSchemaSize);
        
        int currentIndex = 0;
        for (int parameter : suspiciousParameters) {
            if (currentIndex < firstSubSchemaSize) {
                subParametersOne.add(parameter);
            } else {
                subParametersTwo.add(parameter);
            }
            currentIndex++;
        }
    }
    
    private void makeIsolationTestInput() {
        nextExpectedTestInput = new int[currentFailedTestInput.length];
        
        for (int parameter = 0; parameter < nextExpectedTestInput.length; parameter++) {
            if (unrelatedParameters.contains(parameter) || subParametersOne.contains(parameter)) {
                final int otherValueIndex = (currentFailedTestInput[parameter] + 1) % testModel.getSizeOfParameter(parameter);
                nextExpectedTestInput[parameter] = otherValueIndex;
            } else {
                nextExpectedTestInput[parameter] = currentFailedTestInput[parameter];
            }
        }
        
        state = State.ISOLATION;
    }
    
    private void continueIsolationWithNextTestResult() {
        if (coveringArray.getBoolean(wrap(nextExpectedTestInput))) {
            suspiciousParameters = subParametersOne;
        } else {
            suspiciousParameters = subParametersTwo;
            unrelatedParameters.addAll(subParametersOne);
        }
        divideSuspiciousSchemaAndExecuteTestInput();
    }
    
    private void checkIfFurtherIsolationNeededWithTestResult() {
        if (coveringArray.getBoolean(wrap(nextExpectedTestInput))) {
            findNextSuspiciousSchemaAndInvokeIsolation();
        } else {
            failureInducingCombinations.add(constructFailureInducingCombination());
            initializeNextFailedTestInput();
        }
    }
    
    private int[] constructFailureInducingCombination() {
        int[] failureInducingCombination = new int[currentFailedTestInput.length];
        
        for (int parameter = 0; parameter < failureInducingCombination.length; parameter++) {
            if (relatedParameters.contains(parameter)) {
                failureInducingCombination[parameter] = currentFailedTestInput[parameter];
            } else {
                failureInducingCombination[parameter] = NO_VALUE;
            }
        }
        
        return failureInducingCombination;
    }
    
    @Override
    public List<int[]> computeFailureInducingCombinations() {
        return failureInducingCombinations;
    }
    
    private enum State {
        
        INITIALIZATION, ISOLATION, CHECK
        
    }
    
}
