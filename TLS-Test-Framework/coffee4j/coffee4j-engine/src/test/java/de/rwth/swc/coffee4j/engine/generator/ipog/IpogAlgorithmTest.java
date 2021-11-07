package de.rwth.swc.coffee4j.engine.generator.ipog;

import de.rwth.swc.coffee4j.engine.TestModel;
import de.rwth.swc.coffee4j.engine.util.CombinationUtil;
import de.rwth.swc.coffee4j.engine.util.Combinator;
import de.rwth.swc.coffee4j.engine.util.IntArrayWrapper;
import it.unimi.dsi.fastutil.ints.Int2IntMap;
import it.unimi.dsi.fastutil.ints.Int2IntOpenHashMap;
import it.unimi.dsi.fastutil.ints.IntSet;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.IntStream;

import static de.rwth.swc.coffee4j.engine.util.Combinator.computeParameterCombinations;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class IpogAlgorithmTest {

    @Test
    void minimalTest() {
        final TestModel model = new TestModel(1, new int[]{2, 3, 4},
                Collections.emptyList(), Collections.emptyList());

        final List<int[]> testSuite = new IpogAlgorithm(IpogConfiguration.ipogConfiguration()
                .testModel(model)
                .build()
        ).generate();

        verifyAllCombinationsPresent(testSuite, model.getParameterSizes(), model.getStrength());
    }

    @Test
    void oneParameterTwoValueModel() {
        final TestModel model = new TestModel(1, new int[]{2}, Collections.emptyList(), Collections.emptyList());
        
        final List<int[]> testSuite = new IpogAlgorithm(IpogConfiguration.ipogConfiguration().testModel(model).build()).generate();
        
        assertEquals(2, testSuite.size());
        assertEquals(1, testSuite.get(0).length);
        assertEquals(1, testSuite.get(1).length);
        assertEquals(0, testSuite.get(0)[0]);
        assertEquals(1, testSuite.get(1)[0]);
    }
    
    @Test
    void itShouldCoverEachValueOnceForStrengthOneWithMultipleParameters() {
        final TestModel model = new TestModel(1, new int[]{4, 4, 4, 4},
                Collections.emptyList(), Collections.emptyList());
        
        final List<int[]> testSuite = new IpogAlgorithm(IpogConfiguration.ipogConfiguration().testModel(model).build()).generate();
        final List<int[]> expectedTestInputs = Arrays.asList(
                new int[]{0, 0, 0, 0},
                new int[]{1, 1, 1, 1},
                new int[]{2, 2, 2, 2},
                new int[]{3, 3, 3, 3});
        
        Assertions.assertEquals(IntArrayWrapper.wrapToSet(expectedTestInputs), IntArrayWrapper.wrapToSet(testSuite));
    }
    
    @Test
    void itShouldGenerateCartesianProductIfStrengthIsNumberOfParameters() {
        final TestModel model = new TestModel(7, new int[]{5, 5, 5, 5, 5, 5, 5}, Collections.emptyList(), Collections.emptyList());
        
        final List<int[]> testSuite = new IpogAlgorithm(IpogConfiguration.ipogConfiguration().testModel(model).build()).generate();
        
        final Int2IntMap parameterMap = new Int2IntOpenHashMap(new int[]{0, 1, 2, 3, 4, 5, 6}, new int[]{5, 5, 5, 5, 5, 5, 5});
        assertEquals(IntArrayWrapper.wrapToSet(Combinator.computeCartesianProduct(parameterMap, 7)), IntArrayWrapper.wrapToSet(testSuite));
    }
    
    @Test
    void itShouldGenerateAllNeededTestInputsIfSmallerStrength() {
        final TestModel model = new TestModel(2, new int[]{3, 3, 3, 3},
                Collections.emptyList(), Collections.emptyList());
        
        final List<int[]> testSuite = new IpogAlgorithm(IpogConfiguration.ipogConfiguration()
                .testModel(model)
                .build()
        ).generate();
        
        verifyAllCombinationsPresent(testSuite, model.getParameterSizes(), 2);
    }
    
    private static void verifyAllCombinationsPresent(List<int[]> testSuite, int[] parameterSizes, int strength) {
        final List<IntSet> parameterCombinations =
                computeParameterCombinations(IntStream.range(0, parameterSizes.length).toArray(), strength);
        
        for (IntSet parameterCombination : parameterCombinations) {
            final List<int[]> combinations = computeCartesianProduct(parameterCombination, parameterSizes);
            
            for (int[] combination : combinations) {
                assertTrue(containsCombination(testSuite, combination), () -> "" + Arrays.toString(combination) + " missing.");
            }
        }
    }
    
    private static List<int[]> computeCartesianProduct(IntSet parameterCombination, int[] parameterSizes) {
        final Int2IntMap parameterSizeMap = new Int2IntOpenHashMap(parameterSizes.length);
        
        for (int parameter : parameterCombination) {
            parameterSizeMap.put(parameter, parameterSizes[parameter]);
        }
        
        return Combinator.computeCartesianProduct(parameterSizeMap, parameterSizes.length);
    }
    
    private static boolean containsCombination(List<int[]> testSuite, int[] combination) {
        for (int[] testInput : testSuite) {
            if (CombinationUtil.contains(testInput, combination)) {
                return true;
            }
        }
        return false;
    }
    
    @Test
    void itShouldCoverAllCombinationsIfParametersHaveDifferentSizes() {
        final TestModel model = new TestModel(2, new int[]{2, 5, 3, 2, 4},
                Collections.emptyList(), Collections.emptyList());
        
        final List<int[]> testSuite = new IpogAlgorithm(IpogConfiguration.ipogConfiguration().testModel(model).build()).generate();
        
        verifyAllCombinationsPresent(testSuite, model.getParameterSizes(), 2);
    }
}
