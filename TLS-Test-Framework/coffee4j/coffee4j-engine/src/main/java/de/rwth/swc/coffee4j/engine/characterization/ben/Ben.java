package de.rwth.swc.coffee4j.engine.characterization.ben;

import de.rwth.swc.coffee4j.engine.TestResult;
import de.rwth.swc.coffee4j.engine.characterization.FaultCharacterizationAlgorithm;
import de.rwth.swc.coffee4j.engine.characterization.FaultCharacterizationAlgorithmFactory;
import de.rwth.swc.coffee4j.engine.characterization.FaultCharacterizationConfiguration;
import de.rwth.swc.coffee4j.engine.characterization.SuspiciousCombinationAlgorithm;
import de.rwth.swc.coffee4j.engine.util.CombinationUtil;
import de.rwth.swc.coffee4j.engine.util.Combinator;
import de.rwth.swc.coffee4j.engine.util.IntArrayWrapper;
import de.rwth.swc.coffee4j.engine.util.Preconditions;
import it.unimi.dsi.fastutil.ints.IntArrayList;
import it.unimi.dsi.fastutil.ints.IntList;
import it.unimi.dsi.fastutil.objects.Object2DoubleMap;
import it.unimi.dsi.fastutil.objects.Object2DoubleOpenHashMap;
import it.unimi.dsi.fastutil.objects.Object2IntMap;
import it.unimi.dsi.fastutil.objects.Object2IntOpenHashMap;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Comparator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static de.rwth.swc.coffee4j.engine.util.CombinationUtil.NO_VALUE;
import static de.rwth.swc.coffee4j.engine.util.IntArrayWrapper.wrap;
import static de.rwth.swc.coffee4j.engine.util.PredicateUtil.not;

/**
 * The implementation of the BEN fault characterization algorithm based on the paper "Identifying Failure-Inducing
 * Combinations in a Combinatorial Test Set". Generates multiple sets of new test inputs if necessary. This means it is
 * not known at which iteration an empty list is returned to signal the algorithm is stopping. Failure-Inducing
 * combinations are ranked by an internal measure of probability. This means that combinations at the beginning of the
 * returned list are more likely to be failure-inducing. The list of failure-inducing combinations is build out of lists
 * for each combination size. That means first all 1-value-combinations are returned in probability order, then all
 * two-value-combinations, ..., then all t-value combinations where t is the testing strength.
 * <p>
 * Internally, the algorithm works with two important structures: t-value-combinations and so called components
 * (1-value-combinations). In each iteration all components are ranked according to appearance in failed or successful
 * test inputs as well as suspicious combinations. Next, all suspicious t-value combinations (those combinations
 * appearing in only failed test inputs) are ranked according to the suspiciousness of their contained components, and
 * other components in their test inputs. Consider the following example: There is a failed test input (1, 2, 3) when
 * testing with strength 2. (1, 2, -) appears in no successful test input so its a suspicious combinations. 1 appears in
 * many failed test inputs and suspicious combinations in the whole test suite and it is therefore likely that some
 * failure-inducing combinations contains 1. With 2, the same story is the input. 3 does not appear in any failed test
 * input at all. This means (1, 2, -) is very likely the combination causing the failure of (1, 2, 3).
 * Of course, a combination with fewer than t values can also be failure inducing. Therefore, BEN recudes all t-value-
 * combinations at the end. This is done by looking if all possible containing combinations are suspicious.
 * For example, if each parameter has 2 values and (0, 1) and (0, 2) are suspicious, (0, -) is therefore also suspicious
 * since there is no non-suspicious combination containing (0, -).
 * <p>
 * Important Information:
 * -Will not find any failure-inducing combination involving more than t parameters. If you expect such failure-inducing
 * combinations, your t is already chose wrong
 * -Can generate many additional test inputs if needed. The number of generated test inputs per iteration is configurable
 * -Orders failure-inducing combinations by probability
 * -Considers constraints as an addition to the original algorithm
 * -Not very efficient if failure-inducing combination is smaller than t values
 */
public class Ben extends SuspiciousCombinationAlgorithm {
    
    private static final int DEFAULT_NUMBER_OF_COMBINATIONS_PER_STEP = 10;
    private static final int DEFAULT_MAX_GENERATION_ATTEMPTS = 50;
    
    private final int numberOfCombinationsPerStep;
    private final int maxGenerationAttempts;
    
    private boolean endInNextIteration = false;
    
    /**
     * Builds a new instance of the algorithm for a given configuration. 10 test inputs will be generated per step, and
     * no further test inputs are generated in the next iteration if no test input can be found for a failure inducing
     * combinations after 50 attempts.
     *
     * @param configuration for knowing which combinations can be failure-inducing/which test inputs can be generated.
     *                      Must not be {@code null}
     * @throws NullPointerException if configuration is {@code null}
     */
    public Ben(FaultCharacterizationConfiguration configuration) {
        this(configuration, DEFAULT_NUMBER_OF_COMBINATIONS_PER_STEP, DEFAULT_MAX_GENERATION_ATTEMPTS);
    }
    
    /**
     * Builds a new instance of the algorithm for the given configuration.
     *
     * @param configuration               for knowing which combinations can be failure-inducing/which test inputs can be generated.
     *                                    Must not be {@code null}
     * @param numberOfCombinationsPerStep how many test inputs should be generated per step. Must be positive
     * @param maxGenerationAttempts       after how many attempts the algorithm should give up on generating a previously
     *                                    untested test inputs containing a given failure-inducing combination. Must be positive
     * @throws NullPointerException     if configuration is {@code null}
     * @throws IllegalArgumentException if one of the integers is not positive
     */
    public Ben(FaultCharacterizationConfiguration configuration, int numberOfCombinationsPerStep, int maxGenerationAttempts) {
        super(configuration);
        Preconditions.check(numberOfCombinationsPerStep > 0);
        Preconditions.check(maxGenerationAttempts > 0);
        
        this.numberOfCombinationsPerStep = numberOfCombinationsPerStep;
        this.maxGenerationAttempts = maxGenerationAttempts;
    }
    
    /**
     * Can be used as a convenience method to describe that BEN should be used as a
     * {@link FaultCharacterizationAlgorithmFactory}.
     *
     * @return a factory using ben as a fault characterization algorithm. Each instance of BEN is configured to create 10
     * new test inputs per iteration and uses 50 generation attempts before considering a combination to
     * be failure-inducing
     */
    public static FaultCharacterizationAlgorithmFactory ben() {
        return configuration -> new Ben(configuration, DEFAULT_NUMBER_OF_COMBINATIONS_PER_STEP, DEFAULT_MAX_GENERATION_ATTEMPTS);
    }
    
    /**
     * Can be used as a convenience method to describe that BEN should be used as a
     * {@link FaultCharacterizationAlgorithmFactory}.
     *
     * @param numberOfCombinationsPerStep see {@link Ben#Ben(FaultCharacterizationConfiguration, int, int)}
     * @param maxGenerationAttempts       see {@link Ben#Ben(FaultCharacterizationConfiguration, int, int)}
     * @return a factory using the constructor ({@link Ben#Ben(FaultCharacterizationConfiguration, int, int)}) to create new
     * {@link FaultCharacterizationAlgorithm} instances
     * @throws IllegalArgumentException if one of the integers is not positive
     */
    public static FaultCharacterizationAlgorithmFactory ben(int numberOfCombinationsPerStep, int maxGenerationAttempts) {
        Preconditions.check(numberOfCombinationsPerStep > 0);
        Preconditions.check(maxGenerationAttempts > 0);
        
        return configuration -> new Ben(configuration, numberOfCombinationsPerStep, maxGenerationAttempts);
    }
    
    @Override
    public Set<IntArrayWrapper> getRelevantSubCombinations(int[] combination) {
        return Combinator.computeSubCombinations(combination, getModel().getStrength()).stream().map(IntArrayWrapper::new).collect(Collectors.toSet());
    }
    
    @Override
    public boolean shouldGenerateFurtherTestInputs() {
        return previousSuspiciousCombinations.size() != suspiciousCombinations.size() && !endInNextIteration && getModel().getStrength() < getModel().getNumberOfParameters();
    }
    
    @Override
    public List<IntArrayWrapper> generateNextTestInputs(Map<int[], TestResult> newTestResults) {
        final Object2DoubleMap<Component> componentSuspiciousnessMap = computeComponentSuspiciousness(suspiciousCombinations);
        final List<IntArrayWrapper> suspiciousCombinationsRanking = computeSuspiciousCombinationsRanking(componentSuspiciousnessMap, suspiciousCombinations);
        final int numberOfNewTestInputs = Math.min(suspiciousCombinationsRanking.size(), numberOfCombinationsPerStep);
        final List<IntArrayWrapper> newTestInputs = new ArrayList<>(numberOfNewTestInputs);
        for (int i = 0; i < numberOfNewTestInputs; i++) {
            final int[] currentCombination = suspiciousCombinationsRanking.get(i).getArray();
            final IntArrayWrapper newTestInput = computeNewTestInputFor(currentCombination, componentSuspiciousnessMap);
            if (newTestInput != null) {
                newTestInputs.add(newTestInput);
            } else {
                endInNextIteration = true;
            }
        }
        
        return newTestInputs;
    }
    
    private Object2DoubleMap<Component> computeComponentSuspiciousness(Set<IntArrayWrapper> relevantSuspiciousCombinations) {
        final Object2IntMap<Component> numberOfFailedTestAppearances = new Object2IntOpenHashMap<>();
        final Object2IntMap<Component> numberOfTestAppearances = new Object2IntOpenHashMap<>();
        final Object2IntMap<Component> numberOfCombinationsAppearances = new Object2IntOpenHashMap<>();
        final int numberOfSuspiciousCombinations = relevantSuspiciousCombinations.size();
        int numberOfFailedTestInputs = 0;
        
        for (Map.Entry<IntArrayWrapper, TestResult> entry : testResults.entrySet()) {
            final int[] currentCombination = entry.getKey().getArray();
            for (int parameter = 0; parameter < currentCombination.length; parameter++) {
                final Component component = new Component(parameter, currentCombination[parameter]);
                numberOfTestAppearances.put(component, numberOfTestAppearances.getOrDefault(component, 0) + 1);
                if (entry.getValue().isUnsuccessful()) {
                    numberOfFailedTestAppearances.put(component, numberOfFailedTestAppearances.getOrDefault(component, 0) + 1);
                }
            }
            if (entry.getValue().isUnsuccessful()) {
                numberOfFailedTestInputs++;
            }
        }
        for (IntArrayWrapper suspiciousCombination : relevantSuspiciousCombinations) {
            final int[] suspiciousCombinationArray = suspiciousCombination.getArray();
            for (int parameter = 0; parameter < suspiciousCombinationArray.length; parameter++) {
                final Component component = new Component(parameter, suspiciousCombinationArray[parameter]);
                numberOfCombinationsAppearances.put(component, numberOfCombinationsAppearances.getOrDefault(component, 0) + 1);
            }
        }
        
        final Object2DoubleMap<Component> componentSuspiciousnessMap = new Object2DoubleOpenHashMap<>();
        for (int parameter = 0; parameter < getModel().getNumberOfParameters(); parameter++) {
            for (int value = 0; value < getModel().getSizeOfParameter(parameter); value++) {
                final Component component = new Component(parameter, value);
                final int failedTestAppearances = numberOfFailedTestAppearances.getOrDefault(component, 0);
                final int testAppearances = numberOfTestAppearances.getOrDefault(component, 0);
                final int combinationAppearances = numberOfCombinationsAppearances.getOrDefault(component, 0);
                final double suspiciousness = (zeroSafeDivision(failedTestAppearances, numberOfFailedTestInputs) + failedTestAppearances / (double) testAppearances + combinationAppearances / (double) numberOfSuspiciousCombinations) / 3.0;
                componentSuspiciousnessMap.put(component, suspiciousness);
            }
        }
        
        return componentSuspiciousnessMap;
    }
    
    private double zeroSafeDivision(double value, double divisor) {
        return divisor == 0 ? 0 : value / divisor;
    }
    
    private List<IntArrayWrapper> computeSuspiciousCombinationsRanking(Object2DoubleMap<Component> componentSuspiciousnessMap, Set<IntArrayWrapper> relevantSuspiciousCombinations) {
        final List<IntArrayWrapper> suspiciousnessOfCombinationRanking = computeSuspiciousnessOfCombinationRanking(componentSuspiciousnessMap, relevantSuspiciousCombinations);
        final List<IntArrayWrapper> suspiciousnessOfEnvironmentRanking = computeSuspiciousnessOfEnvironmentRanking(componentSuspiciousnessMap, relevantSuspiciousCombinations);
        
        return relevantSuspiciousCombinations.stream().sorted(Comparator.comparingInt(combination -> suspiciousnessOfCombinationRanking.indexOf(combination) + suspiciousnessOfEnvironmentRanking.indexOf(combination))).collect(Collectors.toList());
    }
    
    private List<IntArrayWrapper> computeSuspiciousnessOfCombinationRanking(Object2DoubleMap<Component> componentSuspiciousnessMap, Set<IntArrayWrapper> relevantSuspiciousCombinations) {
        final Object2DoubleMap<IntArrayWrapper> suspiciousnessOfCombinations = new Object2DoubleOpenHashMap<>();
        for (IntArrayWrapper combination : relevantSuspiciousCombinations) {
            final int[] combinationArray = combination.getArray();
            double sum = 0;
            double numberOfParameters = 0;
            
            for (int parameter = 0; parameter < combinationArray.length; parameter++) {
                if (combinationArray[parameter] != NO_VALUE) {
                    final Component component = new Component(parameter, combinationArray[parameter]);
                    sum += componentSuspiciousnessMap.getDouble(component);
                    numberOfParameters++;
                }
            }
            
            suspiciousnessOfCombinations.put(combination, zeroSafeDivision(sum, numberOfParameters));
        }
        List<IntArrayWrapper> suspiciousnessOfCombinationRanking = new ArrayList<>(relevantSuspiciousCombinations);
        suspiciousnessOfCombinationRanking.sort(Comparator.comparing(suspiciousnessOfCombinations::getDouble).reversed());
        
        return suspiciousnessOfCombinationRanking;
    }
    
    private List<IntArrayWrapper> computeSuspiciousnessOfEnvironmentRanking(Object2DoubleMap<Component> componentSuspiciousnessMap, Set<IntArrayWrapper> relevantSuspiciousCombinations) {
        final Object2DoubleMap<IntArrayWrapper> suspiciousnessOfEnvironment = new Object2DoubleOpenHashMap<>();
        for (IntArrayWrapper combination : relevantSuspiciousCombinations) {
            final double minimumAverage = computeMinimumAverage(combination.getArray(), componentSuspiciousnessMap);
            suspiciousnessOfEnvironment.put(combination, minimumAverage);
        }
        List<IntArrayWrapper> suspiciousnessOfEnvironmentRanking = new ArrayList<>(relevantSuspiciousCombinations);
        suspiciousnessOfEnvironmentRanking.sort(Comparator.comparing(suspiciousnessOfEnvironment::getDouble));
        
        return suspiciousnessOfEnvironmentRanking;
    }
    
    private double computeMinimumAverage(int[] combinationArray, Object2DoubleMap<Component> componentSuspiciousnessMap) {
        double minimumAverage = Double.MAX_VALUE;
        
        for (IntArrayWrapper testInput : testResults.keySet()) {
            final int[] testInputArray = testInput.getArray();
            if (CombinationUtil.contains(testInputArray, combinationArray)) {
                double sum = 0;
                int numberOfParameters = 0;
                
                for (int parameter = 0; parameter < testInputArray.length; parameter++) {
                    if (combinationArray[parameter] == NO_VALUE) {
                        final Component component = new Component(parameter, testInputArray[parameter]);
                        sum += componentSuspiciousnessMap.getDouble(component);
                        numberOfParameters++;
                    }
                }
                final double average = zeroSafeDivision(sum, numberOfParameters);
                if (average < minimumAverage) {
                    minimumAverage = average;
                }
            }
        }
        
        return minimumAverage;
    }
    
    private IntArrayWrapper computeNewTestInputFor(int[] subCombination, Object2DoubleMap<Component> componentSuspiciousnessMap) {
        final IntList[] parameterValueRanking = computeParameterValueRanking(componentSuspiciousnessMap);
        final IntList environmentParameters = computeEnvironmentParameters(subCombination);
        final int[] newTestInputArray = computeLowestEnvironmentSuspicionTestInput(subCombination, parameterValueRanking);
        final IntArrayWrapper newTestInput = wrap(newTestInputArray);
        final Random random = new Random();
        
        for (int i = 0; i < maxGenerationAttempts && testResults.containsKey(newTestInput) && getChecker().isValid(newTestInputArray); i++) {
            final int changingParameter = environmentParameters.getInt(random.nextInt(environmentParameters.size()));
            final IntList valueRanking = parameterValueRanking[changingParameter];
            final int currentValue = newTestInputArray[changingParameter];
            final int nextValueIndex = (valueRanking.indexOf(currentValue) + 1) % valueRanking.size();
            final int nextValue = valueRanking.getInt(nextValueIndex);
            newTestInputArray[changingParameter] = nextValue;
        }
        
        return testResults.containsKey(newTestInput) ? null : newTestInput;
    }
    
    private IntList[] computeParameterValueRanking(Object2DoubleMap<Component> componentSuspiciousnessMap) {
        final int numberOfParameter = getModel().getNumberOfParameters();
        final IntList[] parameterValueRanking = new IntList[numberOfParameter];
        
        for (int parameter = 0; parameter < numberOfParameter; parameter++) {
            final int finalParameter = parameter;
            parameterValueRanking[parameter] = new IntArrayList(IntStream.range(0, getModel().getSizeOfParameter(parameter)).boxed().sorted(Comparator.comparingDouble(value -> componentSuspiciousnessMap.getDouble(new Component(finalParameter, value)))).mapToInt(Integer::intValue).toArray());
        }
        
        return parameterValueRanking;
    }
    
    private IntList computeEnvironmentParameters(int[] subCombination) {
        final IntList environmentParameters = new IntArrayList();
        
        for (int parameter = 0; parameter < subCombination.length; parameter++) {
            if (subCombination[parameter] == NO_VALUE) {
                environmentParameters.add(parameter);
            }
        }
        
        return environmentParameters;
    }
    
    private int[] computeLowestEnvironmentSuspicionTestInput(int[] subCombination, IntList[] parameterValueRanking) {
        int[] testInput = Arrays.copyOf(subCombination, subCombination.length);
        
        for (int parameter = 0; parameter < subCombination.length; parameter++) {
            if (testInput[parameter] == NO_VALUE) {
                testInput[parameter] = parameterValueRanking[parameter].getInt(0);
            }
        }
        
        return testInput;
    }
    
    @Override
    public List<int[]> computeFailureInducingCombinations() {
        final List<Set<IntArrayWrapper>> suspiciousCombinationsByStrength = new LinkedList<>();
        suspiciousCombinationsByStrength.add(suspiciousCombinations);
        for (int i = getModel().getStrength() - 1; i > 0; i--) {
            suspiciousCombinationsByStrength.add(0, SuspiciousCombinationReducer.reduce(getModel().getParameterSizes(), suspiciousCombinationsByStrength.get(0)));
        }
        
        return suspiciousCombinationsByStrength.stream().filter(not(Collection::isEmpty)).map(this::computeSuspiciousCombinationsRanking).flatMap(List::stream).map(IntArrayWrapper::getArray).collect(Collectors.toList());
    }
    
    private List<IntArrayWrapper> computeSuspiciousCombinationsRanking(Set<IntArrayWrapper> suspiciousCombinations) {
        return computeSuspiciousCombinationsRanking(computeComponentSuspiciousness(suspiciousCombinations), suspiciousCombinations);
    }
    
    private static final class Component {
        
        private final int parameter;
        private final int value;
        
        private Component(int parameter, int value) {
            this.parameter = parameter;
            this.value = value;
        }
        
        @Override
        public int hashCode() {
            int result = parameter;
            result = 31 * result + value;
            
            return result;
        }
        
        @Override
        public boolean equals(Object object) {
            if (object == null || getClass() != object.getClass()) {
                return false;
            }
            
            Component other = (Component) object;
            
            return parameter == other.parameter && value == other.value;
        }
        
        @Override
        public String toString() {
            return "Component{" + "parameter=" + parameter + ", value=" + value + '}';
        }
        
    }
    
}
