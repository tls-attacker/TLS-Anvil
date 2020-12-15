package de.rwth.swc.coffee4j.engine.util;

import de.rwth.swc.coffee4j.engine.constraint.ConstraintChecker;
import de.rwth.swc.coffee4j.engine.constraint.NoConstraintChecker;
import it.unimi.dsi.fastutil.ints.IntOpenHashSet;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mockito;

import java.util.stream.Stream;

import static de.rwth.swc.coffee4j.engine.util.CombinationUtil.containsAllParameters;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

class CombinationUtilTest {
    
    @Test
    void emptyCombinationCannotHaveNegativeSize() {
        Assertions.assertThrows(IllegalArgumentException.class, () -> CombinationUtil.emptyCombination(-1));
        Assertions.assertThrows(IllegalArgumentException.class, () -> CombinationUtil.emptyCombination(-312));
    }
    
    @Test
    void createsEmptyCombinations() {
        Assertions.assertArrayEquals(new int[0], CombinationUtil.emptyCombination(0));
        Assertions.assertArrayEquals(new int[]{CombinationUtil.NO_VALUE}, CombinationUtil.emptyCombination(1));
        Assertions.assertArrayEquals(new int[]{CombinationUtil.NO_VALUE, CombinationUtil.NO_VALUE, CombinationUtil.NO_VALUE}, CombinationUtil.emptyCombination(3));
    }
    
    @Test
    void containsThrowsIfNotSameLengthOrNull() {
        Assertions.assertThrows(NullPointerException.class, () -> CombinationUtil.contains(null, new int[0]));
        Assertions.assertThrows(NullPointerException.class, () -> CombinationUtil.contains(new int[0], null));
        Assertions.assertThrows(IllegalArgumentException.class, () -> CombinationUtil.contains(new int[0], new int[]{1}));
        Assertions.assertThrows(IllegalArgumentException.class, () -> CombinationUtil.contains(new int[]{1, 2}, new int[]{1}));
    }
    
    @ParameterizedTest
    @MethodSource
    void containsTests(int[] first, int[] second, boolean shouldContain) {
        Assertions.assertEquals(shouldContain, CombinationUtil.contains(first, second));
    }
    
    private static Stream<Arguments> containsTests() {
        return Stream.of(arguments(new int[0], new int[0], true), arguments(new int[]{0, 1}, CombinationUtil.emptyCombination(2), true), arguments(new int[]{0, 1}, new int[]{0, CombinationUtil.NO_VALUE}, true), arguments(new int[]{0, 1}, new int[]{0, 1}, true), arguments(new int[]{0, CombinationUtil.NO_VALUE}, new int[]{0, 1}, false), arguments(new int[]{0, 1}, new int[]{1, 1}, false));
    }
    
    @Test
    void canBeAddedHaveToBeSameLengthAndNotNull() {
        Assertions.assertThrows(NullPointerException.class, () -> CombinationUtil.canBeAdded(null, new int[0], new NoConstraintChecker()));
        Assertions.assertThrows(NullPointerException.class, () -> CombinationUtil.canBeAdded(new int[]{0}, null, new NoConstraintChecker()));
        Assertions.assertThrows(NullPointerException.class, () -> CombinationUtil.canBeAdded(new int[]{0}, new int[]{0}, null));
        Assertions.assertThrows(IllegalArgumentException.class, () -> CombinationUtil.canBeAdded(new int[]{0}, new int[]{0, 0}, new NoConstraintChecker()));
    }
    
    @ParameterizedTest
    @MethodSource
    void canBeAddedTests(int[] combination, int[] toBeAdded, boolean constraintSolverResult, boolean expectedResult) {
        final ConstraintChecker solver = Mockito.mock(ConstraintChecker.class);
        when(solver.isExtensionValid(any(), any())).thenReturn(constraintSolverResult);
        
        Assertions.assertEquals(expectedResult, CombinationUtil.canBeAdded(combination, toBeAdded, solver));
    }
    
    private static Stream<Arguments> canBeAddedTests() {
        return Stream.of(arguments(new int[0], new int[0], true, true), arguments(new int[]{0}, new int[]{1}, true, false), arguments(new int[]{0}, new int[]{0}, true, true), arguments(new int[]{CombinationUtil.NO_VALUE}, new int[]{1}, true, true), arguments(new int[]{CombinationUtil.NO_VALUE}, new int[]{1}, false, false), arguments(new int[]{CombinationUtil.NO_VALUE, 1}, new int[]{0, 1}, true, true), arguments(new int[]{CombinationUtil.NO_VALUE, 1}, new int[]{0, 1}, false, false));
    }
    
    @Test
    void addMustBeSameSizeAndNotNull() {
        assertThrows(NullPointerException.class, () -> CombinationUtil.add(null, new int[0]));
        assertThrows(NullPointerException.class, () -> CombinationUtil.add(new int[0], null));
        assertThrows(IllegalArgumentException.class, () -> CombinationUtil.add(new int[]{0}, new int[]{0, 1}));
    }
    
    @ParameterizedTest
    @MethodSource
    void addTests(int[] combination, int[] toBeAdded, int[] expectedResult) {
        CombinationUtil.add(combination, toBeAdded);
        assertArrayEquals(expectedResult, combination);
    }
    
    private static Stream<Arguments> addTests() {
        return Stream.of(arguments(new int[0], new int[0], new int[0]), arguments(new int[]{1}, new int[]{1}, new int[]{1}), arguments(new int[]{CombinationUtil.NO_VALUE}, new int[]{1}, new int[]{1}), arguments(new int[]{1, CombinationUtil.NO_VALUE}, new int[]{CombinationUtil.NO_VALUE, 0}, new int[]{1, 0}));
    }
    
    @Test
    void containsAllParametersPreconditions() {
        Assertions.assertThrows(NullPointerException.class, () -> CombinationUtil.containsAllParameters(null, new IntOpenHashSet()));
        Assertions.assertThrows(NullPointerException.class, () -> CombinationUtil.containsAllParameters(new int[0], null));
    }
    
    @ParameterizedTest
    @MethodSource
    void containsAllParametersTest(int[] combination, int[] parameters, boolean expectedResult) {
        Assertions.assertEquals(expectedResult, CombinationUtil.containsAllParameters(combination, new IntOpenHashSet(parameters)));
    }
    
    private static Stream<Arguments> containsAllParametersTest() {
        return Stream.of(arguments(new int[]{0}, new int[]{-1}, false), arguments(new int[]{0, 1}, new int[]{2}, false), arguments(new int[0], new int[0], true), arguments(CombinationUtil.emptyCombination(100), new int[]{44}, false), arguments(new int[]{1, 1, 1}, new int[]{0, 2}, true), arguments(new int[]{CombinationUtil.NO_VALUE, 1, CombinationUtil.NO_VALUE}, new int[]{1, 2}, false));
    }
    
    @Test
    void containsAllParametersUntilPreconditions() {
        Assertions.assertThrows(NullPointerException.class, () -> CombinationUtil.containsAllParameters(null, 0));
    }
    
    @ParameterizedTest
    @MethodSource
    void containsAllParametersUntilTests(int[] combination, int until, boolean expectedResult) {
        Assertions.assertEquals(expectedResult, CombinationUtil.containsAllParameters(combination, until));
    }
    
    private static Stream<Arguments> containsAllParametersUntilTests() {
        return Stream.of(arguments(new int[0], -1, true), arguments(new int[0], 0, false), arguments(new int[]{0, 1}, 1, true), arguments(new int[]{0}, 0, true), arguments(new int[]{CombinationUtil.NO_VALUE, 0}, 0, false), arguments(new int[]{CombinationUtil.NO_VALUE, 0}, 1, false), arguments(new int[]{1, 2, CombinationUtil.NO_VALUE}, 1, true), arguments(new int[]{1, 2, CombinationUtil.NO_VALUE}, 2, false));
    }
    
    @Test
    void sameForAllGivenParametersPreconditions() {
        Assertions.assertThrows(NullPointerException.class, () -> CombinationUtil.sameForAllGivenParameters(null, new int[0], new IntOpenHashSet()));
        Assertions.assertThrows(NullPointerException.class, () -> CombinationUtil.sameForAllGivenParameters(new int[0], null, new IntOpenHashSet()));
        Assertions.assertThrows(NullPointerException.class, () -> CombinationUtil.sameForAllGivenParameters(new int[0], new int[0], null));
        
    }
    
    @ParameterizedTest
    @MethodSource
    void sameForAllGivenParametersTests(int[] first, int[] second, int[] parameters, boolean expectedResult) {
        Assertions.assertEquals(expectedResult, CombinationUtil.sameForAllGivenParameters(first, second, new IntOpenHashSet(parameters)));
    }
    
    private static Stream<Arguments> sameForAllGivenParametersTests() {
        return Stream.of(arguments(new int[0], new int[0], new int[]{-1}, true), arguments(new int[]{1}, new int[]{-1}, new int[]{2}, true), arguments(new int[]{0}, new int[]{1}, new int[]{0}, false), arguments(new int[]{1}, new int[]{1}, new int[]{0}, true), arguments(new int[]{0, CombinationUtil.NO_VALUE}, new int[]{1, CombinationUtil.NO_VALUE}, new int[]{1}, true), arguments(new int[]{1, 3, 5, 2, 3, 6}, new int[]{1, 2, 5, 2, 7, 8}, new int[]{0, 2, 3}, true), arguments(new int[]{1, 3, 5, 2, 3, 6}, new int[]{1, 2, 5, 2, 7, 8}, new int[]{1, 2, 3}, false));
    }
    
    @Test
    void numberOfSetParametersPreconditions() {
        Assertions.assertThrows(NullPointerException.class, () -> CombinationUtil.numberOfSetParameters(null));
    }
    
    @ParameterizedTest
    @MethodSource
    void numberOfSetParametersTests(int[] combination, int expectedNumberOfSetParameters) {
        Assertions.assertEquals(expectedNumberOfSetParameters, CombinationUtil.numberOfSetParameters(combination));
    }
    
    private static Stream<Arguments> numberOfSetParametersTests() {
        return Stream.of(arguments(new int[0], 0), arguments(CombinationUtil.emptyCombination(1), 0), arguments(CombinationUtil.emptyCombination(100), 0), arguments(new int[]{0, 1, 2}, 3), arguments(new int[]{CombinationUtil.NO_VALUE, 1, 2, CombinationUtil.NO_VALUE, 1, 2, CombinationUtil.NO_VALUE}, 4));
    }
    
}
