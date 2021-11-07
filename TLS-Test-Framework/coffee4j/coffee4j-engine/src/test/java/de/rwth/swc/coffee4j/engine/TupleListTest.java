package de.rwth.swc.coffee4j.engine;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class TupleListTest {
    
    @ParameterizedTest
    @MethodSource
    void preconditions(int id, int[] involvedParameters, List<int[]> tuples, Class<? extends Exception> expected) {
        assertThrows(expected, () -> new TupleList(id, involvedParameters, tuples));
    }
    
    private static Stream<Arguments> preconditions() {
        return Stream.of(arguments(0, new int[]{0}, Collections.singletonList(new int[]{0}), IllegalArgumentException.class), arguments(-1, new int[]{0}, Collections.singletonList(new int[]{0}), IllegalArgumentException.class), arguments(1, null, Collections.singletonList(new int[]{0}), NullPointerException.class), arguments(1, new int[0], null, IllegalArgumentException.class), arguments(1, new int[]{0}, null, NullPointerException.class), arguments(1, new int[]{0}, Collections.emptyList(), IllegalArgumentException.class), arguments(1, new int[]{0}, Collections.singletonList(new int[0]), IllegalArgumentException.class), arguments(1, new int[]{0, 1}, Arrays.asList(new int[]{0, 0}, new int[]{0}), IllegalArgumentException.class));
    }
    
    @Test
    void testConstruction() {
        final int[] involvedParameters = new int[]{0, 1};
        final List<int[]> tuples = Arrays.asList(new int[]{0, 1}, new int[]{0, 0});
        final TupleList tupleList = new TupleList(2, involvedParameters, tuples);
        
        assertEquals(2, tupleList.getId());
        assertArrayEquals(involvedParameters, tupleList.getInvolvedParameters());
        assertEquals(tuples, tupleList.getTuples());
    }
}
