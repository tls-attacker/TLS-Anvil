package de.rwth.swc.coffee4j.engine.characterization;

import de.rwth.swc.coffee4j.engine.TestModel;
import de.rwth.swc.coffee4j.engine.TestResult;
import de.rwth.swc.coffee4j.engine.constraint.ConstraintChecker;
import de.rwth.swc.coffee4j.engine.constraint.NoConstraintChecker;
import de.rwth.swc.coffee4j.engine.generator.ipog.IpogAlgorithm;
import de.rwth.swc.coffee4j.engine.generator.ipog.IpogConfiguration;
import de.rwth.swc.coffee4j.engine.generator.ipog.ParameterCombinationFactory;
import de.rwth.swc.coffee4j.engine.generator.ipog.TWiseParameterCombinationFactory;
import de.rwth.swc.coffee4j.engine.util.CombinationUtil;
import de.rwth.swc.coffee4j.engine.report.StandardOutputReporter;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public interface FaultCharacterizationAlgorithmTest {
    
    FaultCharacterizationAlgorithm provideAlgorithm(FaultCharacterizationConfiguration configuration);
    
    @ParameterizedTest
    @MethodSource("failureInducingCombinations")
    default void findsRequiredCombinations(int[] parameterSizes, int strength, List<int[]> failureInducingCombinations) {
        final TestModel testModel = new TestModel(strength, parameterSizes, Collections.emptyList(), Collections.emptyList());
        final ConstraintChecker solver = new NoConstraintChecker();
        final ParameterCombinationFactory factory = new TWiseParameterCombinationFactory();
        final FaultCharacterizationAlgorithm faultCharacterizationAlgorithm = provideAlgorithm(new FaultCharacterizationConfiguration(testModel, solver, new StandardOutputReporter()));
        
        List<int[]> testInputs = new IpogAlgorithm(IpogConfiguration.ipogConfiguration().testModel(testModel).checker(solver).factory(factory).build()).generate();
        while (!testInputs.isEmpty()) {
            testInputs = faultCharacterizationAlgorithm.computeNextTestInputs(mapToResults(testInputs, failureInducingCombinations));
        }
        
        assertContainsAllFailureInducingCombinations(faultCharacterizationAlgorithm.computeFailureInducingCombinations(), failureInducingCombinations);
    }
    
    static Map<int[], TestResult> mapToResults(List<int[]> testInputs, List<int[]> failureInducingCombinations) {
        final Map<int[], TestResult> testResults = new HashMap<>();
        
        for (int[] testInput : testInputs) {
            if (containsAny(testInput, failureInducingCombinations)) {
                testResults.put(testInput, TestResult.failure(new IllegalArgumentException()));
            } else {
                testResults.put(testInput, TestResult.success());
            }
        }
        
        return testResults;
    }
    
    static boolean containsAny(int[] testInput, List<int[]> failureInducingCombinations) {
        for (int[] failureInducingCombination : failureInducingCombinations) {
            if (CombinationUtil.contains(testInput, failureInducingCombination)) {
                return true;
            }
        }
        
        return false;
    }
    
    static void assertContainsAllFailureInducingCombinations(List<int[]> foundCombinations, List<int[]> failureInducingCombinations) {
        for (int[] failureInducingCombination : failureInducingCombinations) {
            boolean wasFound = false;
            for (int[] foundCombination : foundCombinations) {
                if (Arrays.equals(failureInducingCombination, foundCombination)) {
                    wasFound = true;
                    break;
                }
            }
            
            if (!wasFound) {
                throw new AssertionError("Could not find combination " + Arrays.toString(failureInducingCombination) + ". Only " + foundCombinations.stream().map(Arrays::toString).collect(Collectors.joining(", ")) + "were found");
            }
        }
    }
    
    static Stream<Arguments> failureInducingCombinations() {
        return Stream.of(Arguments.of(new int[]{2}, 1, Collections.singletonList(new int[]{0})), Arguments.of(new int[]{2}, 1, Collections.singletonList(new int[]{0})), Arguments.of(new int[]{2, 2}, 2, Collections.singletonList(new int[]{0, CombinationUtil.NO_VALUE})), Arguments.of(new int[]{2, 2}, 1, Collections.singletonList(new int[]{0, CombinationUtil.NO_VALUE})), Arguments.of(new int[]{2, 2}, 2, Collections.singletonList(new int[]{1, CombinationUtil.NO_VALUE})), Arguments.of(new int[]{2, 2}, 2, Arrays.asList(new int[]{1, CombinationUtil.NO_VALUE}, new int[]{CombinationUtil.NO_VALUE, 0})), Arguments.of(new int[]{4, 4, 4, 4}, 2, Collections.singletonList(new int[]{CombinationUtil.NO_VALUE, 1, CombinationUtil.NO_VALUE, 3})), Arguments.of(new int[]{4, 4, 4, 4}, 2, Arrays.asList(new int[]{CombinationUtil.NO_VALUE, CombinationUtil.NO_VALUE, 0, 0}, new int[]{CombinationUtil.NO_VALUE, 0, 1, CombinationUtil.NO_VALUE})));
    }
    
}
