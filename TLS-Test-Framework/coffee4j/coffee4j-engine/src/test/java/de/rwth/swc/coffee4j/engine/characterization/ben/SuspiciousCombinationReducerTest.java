package de.rwth.swc.coffee4j.engine.characterization.ben;

import de.rwth.swc.coffee4j.engine.util.CombinationUtil;
import de.rwth.swc.coffee4j.engine.util.IntArrayWrapper;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class SuspiciousCombinationReducerTest {

    @ParameterizedTest
    @MethodSource("combinationReductions")
    void reducesCorrectCombinations(int[] parameterSizes, List<int[]> suspiciousCombinations, List<int[]> expectedReducedCombinations) {
        final Set<IntArrayWrapper> reducedCombinations = SuspiciousCombinationReducer.reduce(parameterSizes, suspiciousCombinations.stream().map(IntArrayWrapper::new).collect(Collectors.toSet()));

        assertEquals(expectedReducedCombinations.stream().map(IntArrayWrapper::new).collect(Collectors.toSet()), reducedCombinations);
    }

    private static Stream<Arguments> combinationReductions() {
        return Stream.of(Arguments.of(new int[]{1}, Collections.emptyList(), Collections.emptyList()), Arguments.of(new int[]{3, 3}, Arrays.asList(new int[]{0, 0}, new int[]{0, 1}), Collections.emptyList()), Arguments.of(new int[]{2, 2}, Arrays.asList(new int[]{0, 0}, new int[]{0, 1}), Collections.singletonList(new int[]{0, CombinationUtil.NO_VALUE})), Arguments.of(new int[]{2, 2}, Arrays.asList(new int[]{0}, new int[]{1}), Collections.emptyList()), Arguments.of(new int[]{3, 3, 3}, Arrays.asList(new int[]{0, 0, 0}, new int[]{0, 0, 1}, new int[]{0, 0, 2}, new int[]{0, 1, 0}, new int[]{0, 1, 1}, new int[]{0, 1, 2}, new int[]{0, 2, 0}, new int[]{0, 2, 1}, new int[]{0, 2, 2}, new int[]{1, 0, 0}, new int[]{1, 0, 1}, new int[]{1, 0, 2}, new int[]{1, 1, 0}, new int[]{1, 1, 1}, new int[]{1, 1, 2}, new int[]{1, 2, 0}, new int[]{1, 2, 1}, new int[]{1, 2, 2}, new int[]{2, 0, 0}, new int[]{2, 0, 1}, new int[]{2, 0, 2}, new int[]{2, 1, 0}, new int[]{2, 1, 1}, new int[]{2, 1, 2}, new int[]{2, 2, 0}, new int[]{2, 2, 1}, new int[]{2, 2, 2}), Arrays.asList(new int[]{0, 0, CombinationUtil.NO_VALUE}, new int[]{0, 1, CombinationUtil.NO_VALUE}, new int[]{0, 2, CombinationUtil.NO_VALUE}, new int[]{1, 0, CombinationUtil.NO_VALUE}, new int[]{1, 1, CombinationUtil.NO_VALUE}, new int[]{1, 2, CombinationUtil.NO_VALUE}, new int[]{2, 0, CombinationUtil.NO_VALUE}, new int[]{2, 1, CombinationUtil.NO_VALUE}, new int[]{2, 2, CombinationUtil.NO_VALUE}, new int[]{0, CombinationUtil.NO_VALUE, 0}, new int[]{0, CombinationUtil.NO_VALUE, 1}, new int[]{0, CombinationUtil.NO_VALUE, 2}, new int[]{1, CombinationUtil.NO_VALUE, 0}, new int[]{1, CombinationUtil.NO_VALUE, 1}, new int[]{1, CombinationUtil.NO_VALUE, 2}, new int[]{2, CombinationUtil.NO_VALUE, 0}, new int[]{2, CombinationUtil.NO_VALUE, 1}, new int[]{2, CombinationUtil.NO_VALUE, 2}, new int[]{CombinationUtil.NO_VALUE, 0, 0}, new int[]{CombinationUtil.NO_VALUE, 0, 1}, new int[]{CombinationUtil.NO_VALUE, 0, 2}, new int[]{CombinationUtil.NO_VALUE, 1, 0}, new int[]{CombinationUtil.NO_VALUE, 1, 1}, new int[]{CombinationUtil.NO_VALUE, 1, 2}, new int[]{CombinationUtil.NO_VALUE, 2, 0}, new int[]{CombinationUtil.NO_VALUE, 2, 1}, new int[]{CombinationUtil.NO_VALUE, 2, 2})), Arguments.of(new int[]{3, 3}, Arrays.asList(new int[]{0, 0}, new int[]{0, 1}, new int[]{0, 2}, new int[]{1, 0}, new int[]{1, 1}, new int[]{2, 0}), Arrays.asList(new int[]{0, CombinationUtil.NO_VALUE}, new int[]{CombinationUtil.NO_VALUE, 0})), Arguments.of(new int[]{2, 2, 2}, Arrays.asList(new int[]{0, 0, CombinationUtil.NO_VALUE}, new int[]{0, 1, CombinationUtil.NO_VALUE}, new int[]{0, CombinationUtil.NO_VALUE, 0}, new int[]{0, CombinationUtil.NO_VALUE, 1}), Collections.singletonList(new int[]{0, CombinationUtil.NO_VALUE, CombinationUtil.NO_VALUE})));
    }

    @ParameterizedTest
    @MethodSource("failingReductions")
    void doesNotReduceIncorrectConfigurations(int[] parameterSizes, List<int[]> suspiciousCombinations, Class<? extends Exception> expectedException) {
        Assertions.assertThrows(expectedException, () -> SuspiciousCombinationReducer.reduce(parameterSizes, suspiciousCombinations == null ? null : suspiciousCombinations.stream().map(IntArrayWrapper::new).collect(Collectors.toSet())));
    }

    private static Stream<Arguments> failingReductions() {
        return Stream.of(Arguments.of(null, Collections.emptyList(), NullPointerException.class), Arguments.of(new int[]{}, null, NullPointerException.class), Arguments.of(new int[]{}, Collections.singletonList(new int[]{0}), IllegalArgumentException.class), Arguments.of(new int[]{3, 3}, Arrays.asList(new int[]{0, CombinationUtil.NO_VALUE}, new int[]{0, 1}), IllegalArgumentException.class));
    }

}
