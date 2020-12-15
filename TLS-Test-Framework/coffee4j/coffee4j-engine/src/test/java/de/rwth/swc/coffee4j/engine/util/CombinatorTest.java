package de.rwth.swc.coffee4j.engine.util;

import it.unimi.dsi.fastutil.ints.Int2IntMap;
import it.unimi.dsi.fastutil.ints.Int2IntOpenHashMap;
import it.unimi.dsi.fastutil.ints.IntArraySet;
import it.unimi.dsi.fastutil.ints.IntOpenHashSet;
import it.unimi.dsi.fastutil.ints.IntSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.params.provider.Arguments.arguments;

/**
 * Test class for {@link Combinator}.
 */
class CombinatorTest {
    
    @Test
    void allParameterValuesReturnedAsCombinationsIfOnlyOneParameter() {
        Int2IntMap parameters = new Int2IntOpenHashMap(new int[]{0}, new int[]{3});
        List<int[]> combinations = Combinator.computeCartesianProduct(parameters, 1);
        
        assertEquals(3, combinations.size());
        assertArrayEquals(new int[]{0}, combinations.get(0));
        assertArrayEquals(new int[]{1}, combinations.get(1));
        assertArrayEquals(new int[]{2}, combinations.get(2));
    }
    
    @Test
    void combinationsAreFilledUpToRequiredSize() {
        Int2IntMap parameters = new Int2IntOpenHashMap(new int[]{0}, new int[]{3});
        List<int[]> combinations = Combinator.computeCartesianProduct(parameters, 4);
        
        assertArrayEquals(new int[]{0, CombinationUtil.NO_VALUE, CombinationUtil.NO_VALUE, CombinationUtil.NO_VALUE}, combinations.get(0));
        assertArrayEquals(new int[]{1, CombinationUtil.NO_VALUE, CombinationUtil.NO_VALUE, CombinationUtil.NO_VALUE}, combinations.get(1));
        assertArrayEquals(new int[]{2, CombinationUtil.NO_VALUE, CombinationUtil.NO_VALUE, CombinationUtil.NO_VALUE}, combinations.get(2));
    }
    
    @Test
    void computeCartesianProductOfTwoParameters() {
        Int2IntMap parameters = new Int2IntOpenHashMap(new int[]{0, 1}, new int[]{4, 4});
        List<int[]> combinations = Combinator.computeCartesianProduct(parameters, 4);
        
        List<int[]> expectedCombinations = new ArrayList<>();
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                expectedCombinations.add(new int[]{j, i, CombinationUtil.NO_VALUE, CombinationUtil.NO_VALUE});
            }
        }
        
        for (int i = 0; i < expectedCombinations.size(); i++) {
            assertArrayEquals(expectedCombinations.get(i), combinations.get(i));
        }
    }
    
    @Test
    void cartesianProductOfMultipleParametersHasRightSize() {
        Int2IntMap parameters = new Int2IntOpenHashMap(new int[]{0, 1, 2, 3, 4, 5}, new int[]{5, 8, 2, 4, 24, 100});
        List<int[]> combinations = Combinator.computeCartesianProduct(parameters, 6);
        
        int expectedNumberOfCombinations = 5 * 8 * 2 * 4 * 24 * 100; //768000
        assertEquals(expectedNumberOfCombinations, combinations.size());
    }
    
    @Test
    void calculateParameterCombinationsWithOneParameter() {
        int[] parameters = new int[]{0};
        List<IntSet> parameterCombinations = Combinator.computeParameterCombinations(parameters, 1);
        
        assertEquals(1, parameterCombinations.size());
        assertEquals(new IntOpenHashSet(Collections.singletonList(0)), parameterCombinations.get(0));
    }
    
    @Test
    void parameterCombinationShouldBeSetItselfIfStrengthEqualsToNumberOfParameters() {
        List<IntSet> parameterCombinations = Combinator.computeParameterCombinations(IntStream.range(0, 100).toArray(), 100);
        
        assertEquals(1, parameterCombinations.size());
        assertEquals(new IntArraySet(IntStream.range(0, 100).toArray()), parameterCombinations.get(0));
    }

    @Test
    void computeCorrectParameterCombinationsForT0() {
        List<IntSet> parameterCombinations = Combinator.computeParameterCombinations(IntStream.range(0, 4).toArray(), 0);

        assertEquals(0, parameterCombinations.size());
    }

    @Test
    void computeCorrectParameterCombinationsForT1() {
        List<IntSet> parameterCombinations = Combinator.computeParameterCombinations(IntStream.range(0, 4).toArray(), 1);

        assertEquals(4, parameterCombinations.size());
        assertTrue(parameterCombinations.contains(new IntOpenHashSet(Arrays.asList(0))));
        assertTrue(parameterCombinations.contains(new IntOpenHashSet(Arrays.asList(1))));
        assertTrue(parameterCombinations.contains(new IntOpenHashSet(Arrays.asList(2))));
        assertTrue(parameterCombinations.contains(new IntOpenHashSet(Arrays.asList(3))));
    }

    @Test
    void computeCorrectParameterCombinationsforT2() {
        List<IntSet> parameterCombinations = Combinator.computeParameterCombinations(IntStream.range(0, 4).toArray(), 2);
        
        assertEquals(6, parameterCombinations.size());
        assertTrue(parameterCombinations.contains(new IntOpenHashSet(Arrays.asList(0, 1))));
        assertTrue(parameterCombinations.contains(new IntOpenHashSet(Arrays.asList(0, 2))));
        assertTrue(parameterCombinations.contains(new IntOpenHashSet(Arrays.asList(0, 3))));
        assertTrue(parameterCombinations.contains(new IntOpenHashSet(Arrays.asList(1, 2))));
        assertTrue(parameterCombinations.contains(new IntOpenHashSet(Arrays.asList(1, 3))));
        assertTrue(parameterCombinations.contains(new IntOpenHashSet(Arrays.asList(2, 3))));
    }
    
    @Test
    void computeNonConsecutiveRightParameterCombinations() {
        int[] parameters = new int[]{0, 2, 3};
        List<IntSet> parameterCombinations = Combinator.computeParameterCombinations(parameters, 2);
        
        assertEquals(3, parameterCombinations.size());
        assertTrue(parameterCombinations.contains(new IntOpenHashSet(Arrays.asList(0, 2))));
        assertTrue(parameterCombinations.contains(new IntOpenHashSet(Arrays.asList(0, 3))));
        assertTrue(parameterCombinations.contains(new IntOpenHashSet(Arrays.asList(2, 3))));
    }
    
    @Test
    void computeNoParameterCombinationsIfSizeTooLarge() {
        int[] parameters = new int[]{0, 1};
        List<IntSet> parameterCombinations = Combinator.computeParameterCombinations(parameters, 3);
        
        assertTrue(parameterCombinations.isEmpty());
    }
    
    @Test
    void shouldWorkWithNonConsecutiveParameters() {
        Int2IntMap parameters = new Int2IntOpenHashMap();
        parameters.put(0, 2);
        parameters.put(3, 2);
        
        List<int[]> combinations = Combinator.computeCartesianProduct(parameters, 4);
        
        assertArrayEquals(new int[]{0, CombinationUtil.NO_VALUE, CombinationUtil.NO_VALUE, 0}, combinations.get(0));
    }
    
    @Test
    void sizeMustBeLargerThanMaxParameterIndex() {
        Int2IntMap parameters = new Int2IntOpenHashMap();
        parameters.put(0, 2);
        parameters.put(5, 2);
        
        assertThrows(IllegalArgumentException.class, () -> Combinator.computeCartesianProduct(parameters, 5));
    }
    
    @Test
    void computeCorrectSingleNegativeParameterCombinationsForT0() {
        int[] negativeParameters = {0};
        
        List<IntSet> result = Combinator.computeNegativeParameterCombinations(IntStream.range(0, 4).toArray(), negativeParameters, 0);
        
        assertEquals(1, result.size());
        assertTrue(result.contains(new IntOpenHashSet(Collections.singletonList(0))));
    }
    
    @Test
    void computeCorrectSingleNegativeParameterCombinationsForT1() {
        int[] negativeParameters = {0};
        
        List<IntSet> result = Combinator.computeNegativeParameterCombinations(IntStream.range(0, 4).toArray(), negativeParameters, 1);
        
        assertEquals(3, result.size());
        assertTrue(result.contains(new IntOpenHashSet(Arrays.asList(0, 1))));
        assertTrue(result.contains(new IntOpenHashSet(Arrays.asList(0, 2))));
        assertTrue(result.contains(new IntOpenHashSet(Arrays.asList(0, 3))));
    }
    
    @Test
    void computeCorrectSingleNegativeParameterCombinationsForT2() {
        int[] negativeParameters = {0};
        
        List<IntSet> result = Combinator.computeNegativeParameterCombinations(IntStream.range(0, 4).toArray(), negativeParameters, 2);
        
        assertEquals(3, result.size());
        assertTrue(result.contains(new IntOpenHashSet(Arrays.asList(0, 1, 2))));
        assertTrue(result.contains(new IntOpenHashSet(Arrays.asList(0, 1, 3))));
        assertTrue(result.contains(new IntOpenHashSet(Arrays.asList(0, 2, 3))));
    }
    
    @Test
    void computeCorrectSingleNegativeParameterCombinationsForT3() {
        int[] negativeParameters = {0};
        
        List<IntSet> result = Combinator.computeNegativeParameterCombinations(IntStream.range(0, 4).toArray(), negativeParameters, 3);
        
        assertEquals(1, result.size());
        assertTrue(result.contains(new IntOpenHashSet(Arrays.asList(0, 1, 2, 3))));
    }
    
    @Test
    void computeCorrectSingleNegativeParameterCombinationsForT4() {
        int[] negativeParameters = {0};
        
        List<IntSet> result = Combinator.computeNegativeParameterCombinations(IntStream.range(0, 4).toArray(), negativeParameters, 4);
        
        assertEquals(1, result.size());
        assertTrue(result.contains(new IntOpenHashSet(Arrays.asList(0, 1, 2, 3))));
    }
    
    @Test
    void computeCorrectSingleNegativeParameterCombinationsForT5() {
        int[] negativeParameters = {0};
        
        List<IntSet> result = Combinator.computeNegativeParameterCombinations(IntStream.range(0, 4).toArray(), negativeParameters, 5);
        
        assertEquals(1, result.size());
        assertTrue(result.contains(new IntOpenHashSet(Arrays.asList(0, 1, 2, 3))));
    }

    @Test
    void computeCorrectPairOfNegativeParameterCombinationsForT0() {
        int[] negativeParameters = {0, 2};

        List<IntSet> result = Combinator.computeNegativeParameterCombinations(IntStream.range(0, 5).toArray(), negativeParameters, 0);

        assertEquals(1, result.size());
        assertTrue(result.contains(new IntOpenHashSet(Arrays.asList(0, 2))));
    }

    @Test
    void computeCorrectPairOfNegativeParameterCombinationsForT1() {
        int[] negativeParameters = {0, 2};
        
        List<IntSet> result = Combinator.computeNegativeParameterCombinations(IntStream.range(0, 5).toArray(), negativeParameters, 1);
        
        assertEquals(3, result.size());
        assertTrue(result.contains(new IntOpenHashSet(Arrays.asList(0, 2, 1))));
        assertTrue(result.contains(new IntOpenHashSet(Arrays.asList(0, 2, 3))));
        assertTrue(result.contains(new IntOpenHashSet(Arrays.asList(0, 2, 4))));
    }

    @Test
    void computeCorrectPairOfNegativeParameterCombinationsForT2() {
        int[] negativeParameters = {0, 2};

        List<IntSet> result = Combinator.computeNegativeParameterCombinations(IntStream.range(0, 5).toArray(), negativeParameters, 2);

        assertEquals(3, result.size());
        assertTrue(result.contains(new IntOpenHashSet(Arrays.asList(0, 2, 1, 3))));
        assertTrue(result.contains(new IntOpenHashSet(Arrays.asList(0, 2, 1, 4))));
        assertTrue(result.contains(new IntOpenHashSet(Arrays.asList(0, 2, 3, 4))));
    }

    @Test
    void computeCorrectPairOfNegativeParameterCombinationsForT3() {
        int[] negativeParameters = {0, 2};

        List<IntSet> result = Combinator.computeNegativeParameterCombinations(IntStream.range(0, 5).toArray(), negativeParameters, 3);

        assertEquals(1, result.size());
        assertTrue(result.contains(new IntOpenHashSet(Arrays.asList(0, 2, 1, 3, 4))));
    }

    @Test
    void computeCorrectPairOfNegativeParameterCombinationsForT4() {
        int[] negativeParameters = {0, 2};

        List<IntSet> result = Combinator.computeNegativeParameterCombinations(IntStream.range(0, 5).toArray(), negativeParameters, 4);

        assertEquals(1, result.size());
        assertTrue(result.contains(new IntOpenHashSet(Arrays.asList(0, 2, 1, 3, 4))));
    }

    @Test
    void computeCorrectPairOfNegativeParameterCombinationsForT5() {
        int[] negativeParameters = {0, 2};

        List<IntSet> result = Combinator.computeNegativeParameterCombinations(IntStream.range(0, 5).toArray(), negativeParameters, 5);

        assertEquals(1, result.size());
        assertTrue(result.contains(new IntOpenHashSet(Arrays.asList(0, 2, 1, 3, 4))));
    }

    @Test
    void computeCorrectExhaustiveNegativeParameterCombinationsForT0() {
        int[] negativeParameters = {0, 1};

        List<IntSet> result = Combinator.computeNegativeParameterCombinations(IntStream.range(0, 2).toArray(), negativeParameters, 0);

        assertEquals(1, result.size());
        assertTrue(result.contains(new IntOpenHashSet(Arrays.asList(0, 1))));
    }

    @Test
    void computeCorrectExhaustiveNegativeParameterCombinationsForT1() {
        int[] negativeParameters = {0, 1};

        List<IntSet> result = Combinator.computeNegativeParameterCombinations(IntStream.range(0, 2).toArray(), negativeParameters, 1);

        assertEquals(1, result.size());
        assertTrue(result.contains(new IntOpenHashSet(Arrays.asList(0, 1))));
    }

    @Test
    void computeCorrectExhaustiveNegativeParameterCombinationsForT2() {
        int[] negativeParameters = {0, 1};

        List<IntSet> result = Combinator.computeNegativeParameterCombinations(IntStream.range(0, 2).toArray(), negativeParameters, 2);

        assertEquals(1, result.size());
        assertTrue(result.contains(new IntOpenHashSet(Arrays.asList(0, 1))));
    }


    @Test
    void preconditionsOfComputeSubCombinationsOfSize() {
        assertThrows(NullPointerException.class, () -> Combinator.computeSubCombinations(null, 1));
        assertThrows(IllegalArgumentException.class, () -> Combinator.computeSubCombinations(CombinationUtil.emptyCombination(2), -1));
    }
    
    @ParameterizedTest
    @MethodSource("sizedSubCombinationTestInputs")
    void combinationHasRightSubCombinationsWithGivenSize(int[] combination, int size, List<int[]> expectedSubCombinations) {
        final List<int[]> computedSubCombinations = Combinator.computeSubCombinations(combination, size);
        final Set<IntArrayWrapper> wrappedComputedSubCombinations = new HashSet<>(IntArrayWrapper.wrapToList(computedSubCombinations));
        final Set<IntArrayWrapper> wrappedExpectedSubCombinations = new HashSet<>(IntArrayWrapper.wrapToList(expectedSubCombinations));
        
        assertEquals(wrappedExpectedSubCombinations, wrappedComputedSubCombinations);
    }
    
    private static Stream<Arguments> sizedSubCombinationTestInputs() {
        return Stream.of(Arguments.of(CombinationUtil.emptyCombination(0), 1, Collections.emptyList()), Arguments.of(CombinationUtil.emptyCombination(0), 100, Collections.emptyList()), Arguments.of(new int[]{1, 2, 3, 4}, 8, Collections.emptyList()), Arguments.of(CombinationUtil.emptyCombination(1), 1, Collections.emptyList()), Arguments.of(CombinationUtil.emptyCombination(6), 1, Collections.emptyList()), Arguments.of(new int[0], 0, Collections.singletonList(CombinationUtil.emptyCombination(0))), Arguments.of(new int[]{1}, 0, Collections.singletonList(CombinationUtil.emptyCombination(1))), Arguments.of(new int[]{0, 1, 2, 3, 4, 5, 6, 7}, 0, Collections.singletonList(CombinationUtil.emptyCombination(8))), Arguments.of(new int[]{1}, 1, Collections.singletonList(new int[]{1})), Arguments.of(new int[]{1, 2, 3, 4, 5}, 1, Arrays.asList(new int[]{1, -1, -1, -1, -1}, new int[]{-1, 2, -1, -1, -1}, new int[]{-1, -1, 3, -1, -1}, new int[]{-1, -1, -1, 4, -1}, new int[]{-1, -1, -1, -1, 5})), Arguments.of(new int[]{-1, 2, -1, 3, -1}, 1, Arrays.asList(new int[]{-1, 2, -1, -1, -1}, new int[]{-1, -1, -1, 3, -1})), Arguments.of(new int[]{1, 2}, 2, Arrays.asList(new int[]{1, 2})), Arguments.of(new int[]{1, 2, 3, 4}, 2, Arrays.asList(new int[]{1, 2, -1, -1}, new int[]{1, -1, 3, -1}, new int[]{1, -1, -1, 4}, new int[]{-1, 2, 3, -1}, new int[]{-1, 2, -1, 4}, new int[]{-1, -1, 3, 4})), Arguments.of(new int[]{-1, 2, -1, 4, -1, 6, -1, 8}, 2, Arrays.asList(new int[]{-1, 2, -1, 4, -1, -1, -1, -1}, new int[]{-1, 2, -1, -1, -1, 6, -1, -1}, new int[]{-1, 2, -1, -1, -1, -1, -1, 8}, new int[]{-1, -1, -1, 4, -1, 6, -1, -1}, new int[]{-1, -1, -1, 4, -1, -1, -1, 8}, new int[]{-1, -1, -1, -1, -1, 6, -1, 8})));
    }
    
    @Test
    void preconditionsOfComputeSubCombinations() {
        assertThrows(NullPointerException.class, () -> Combinator.computeSubCombinations(null));
    }
    
    @ParameterizedTest
    @MethodSource("subCombinationsTestInputs")
    void combinationHasRightSubCombinations(int[] combination, List<int[]> expectedSubCombinations) {
        final List<int[]> computedSubCombinations = Combinator.computeSubCombinations(combination);
        final Set<IntArrayWrapper> wrappedComputedSubCombinations = new HashSet<>(IntArrayWrapper.wrapToList(computedSubCombinations));
        final Set<IntArrayWrapper> wrappedExpectedSubCombinations = new HashSet<>(IntArrayWrapper.wrapToList(expectedSubCombinations));
        
        assertEquals(wrappedExpectedSubCombinations, wrappedComputedSubCombinations);
    }
    
    private static Stream<Arguments> subCombinationsTestInputs() {
        return Stream.of(Arguments.of(CombinationUtil.emptyCombination(0), Collections.emptyList()), Arguments.of(CombinationUtil.emptyCombination(1), Collections.emptyList()), Arguments.of(CombinationUtil.emptyCombination(100), Collections.emptyList()), Arguments.of(new int[]{1}, Collections.singletonList(new int[]{1})), Arguments.of(new int[]{-1, 1}, Collections.singletonList(new int[]{-1, 1})), Arguments.of(new int[]{1, -1}, Collections.singletonList(new int[]{1, -1})), Arguments.of(new int[]{1, 2}, Arrays.asList(new int[]{1, -1}, new int[]{-1, 2}, new int[]{1, 2})), Arguments.of(new int[]{-1, 1, -1, 2}, Arrays.asList(new int[]{-1, 1, -1, -1}, new int[]{-1, -1, -1, 2}, new int[]{-1, 1, -1, 2})), Arguments.of(new int[]{1, 2, 3}, Arrays.asList(new int[]{1, -1, -1}, new int[]{-1, 2, -1}, new int[]{-1, -1, 3}, new int[]{1, 2, -1}, new int[]{1, -1, 3}, new int[]{-1, 2, 3}, new int[]{1, 2, 3})));
    }
    
    @ParameterizedTest
    @MethodSource
    void computeCombinations(int[] parameters, int size, List<int[]> expectedCombinations) {
        final Set<int[]> computedCombinations = Combinator.computeCombinations(parameters, size);
        final Set<IntArrayWrapper> wrappedComputedCombinations = new HashSet<>(IntArrayWrapper.wrapToSet(computedCombinations));
        final Set<IntArrayWrapper> wrappedExpectedCombinations = new HashSet<>(IntArrayWrapper.wrapToList(expectedCombinations));
        
        assertEquals(wrappedExpectedCombinations, wrappedComputedCombinations);
    }
    
    private static Stream<Arguments> computeCombinations() {
        return Stream.of(arguments(new int[0], 0, Collections.emptyList()), arguments(new int[]{2, 2, 2}, 0, Collections.emptyList()), arguments(new int[]{2}, 1, Arrays.asList(new int[]{0}, new int[]{1})), arguments(new int[]{2, 2}, 3, Collections.emptyList()), arguments(new int[]{2, 2}, 1, Arrays.asList(new int[]{0, CombinationUtil.NO_VALUE}, new int[]{1, CombinationUtil.NO_VALUE}, new int[]{CombinationUtil.NO_VALUE, 0}, new int[]{CombinationUtil.NO_VALUE, 1})));
    }
}
