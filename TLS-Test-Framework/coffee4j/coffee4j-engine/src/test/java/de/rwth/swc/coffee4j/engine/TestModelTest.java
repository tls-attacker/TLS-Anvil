package de.rwth.swc.coffee4j.engine;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.Collections;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class TestModelTest {
    
    @ParameterizedTest
    @MethodSource
    void preconditions(int strength, int[] parameterSizes, List<TupleList> forbiddenTupleLists, List<TupleList> errorTupleLists, Class<? extends Exception> expected) {
        assertThrows(expected, () -> new TestModel(strength, parameterSizes, forbiddenTupleLists, errorTupleLists));
    }
    
    private static Stream<Arguments> preconditions() {
        return Stream.of(
                arguments(1, null, Collections.emptyList(), Collections.emptyList(), NullPointerException.class),
                arguments(3, new int[]{2}, Collections.emptyList(), Collections.emptyList(), IllegalArgumentException.class),
                arguments(1, new int[]{2, 2}, null, Collections.emptyList(), NullPointerException.class),
                arguments(1, new int[]{2, 2}, Collections.emptyList(), null, NullPointerException.class),
                arguments(1, new int[]{1, 2}, Collections.emptyList(), Collections.emptyList(), IllegalArgumentException.class),
                arguments(1, new int[]{2, -2}, Collections.emptyList(), Collections.emptyList(), IllegalArgumentException.class),
                arguments(1, new int[]{2, 2}, Collections.singletonList(new TupleList(1, new int[]{-1, 1}, Collections.singletonList(new int[]{0, 0}))), Collections.emptyList(), IllegalArgumentException.class),
                arguments(1, new int[]{2, 2}, Collections.singletonList(new TupleList(1, new int[]{1, 5}, Collections.singletonList(new int[]{0, 0}))), Collections.emptyList(), IllegalArgumentException.class),
                arguments(1, new int[]{2, 2}, Collections.emptyList(), Collections.singletonList(new TupleList(1, new int[]{1, 5}, Collections.singletonList(new int[]{0, 0}))), IllegalArgumentException.class),
                arguments(1, new int[]{2}, Collections.singletonList(new TupleList(1, new int[]{0}, Collections.singletonList(new int[]{0}))), Collections.singletonList(new TupleList(1, new int[]{0}, Collections.singletonList(new int[]{0}))), IllegalArgumentException.class));
    }
    
    @Test
    void constructModel() {
        final List<TupleList> forbiddenTupleLists = Collections.singletonList(new TupleList(1, new int[]{0}, Collections.singletonList(new int[]{0})));
        final List<TupleList> errorTupleLists = Collections.singletonList(new TupleList(2, new int[]{0}, Collections.singletonList(new int[]{1})));
        final int[] parameterSizes = new int[]{2, 3};
        final TestModel model = new TestModel(1, parameterSizes, forbiddenTupleLists, errorTupleLists);
        
        assertEquals(1, model.getStrength());
        assertArrayEquals(parameterSizes, model.getParameterSizes());
        assertEquals(forbiddenTupleLists, model.getForbiddenTupleLists());
        assertEquals(errorTupleLists, model.getErrorTupleLists());
        assertEquals(2, model.getSizeOfParameter(0));
        assertEquals(3, model.getSizeOfParameter(1));
        assertEquals(2, model.getNumberOfParameters());
    }
    
    @Test
    void defaultConstructors() {
        final List<TupleList> forbiddenTupleLists = Collections.singletonList(new TupleList(1, new int[]{0}, Collections.singletonList(new int[]{0})));
        final int[] parameterSizes = new int[]{2, 3};
        TestModel model = new TestModel(2, parameterSizes, Collections.emptyList(), Collections.emptyList());
        
        assertEquals(2, model.getStrength());
        assertArrayEquals(parameterSizes, model.getParameterSizes());
        assertEquals(Collections.emptyList(), model.getForbiddenTupleLists());
        assertEquals(Collections.emptyList(), model.getErrorTupleLists());

        model = new TestModel(2, parameterSizes, forbiddenTupleLists, Collections.emptyList());
        
        assertEquals(2, model.getStrength());
        assertArrayEquals(parameterSizes, model.getParameterSizes());
        assertEquals(forbiddenTupleLists, model.getForbiddenTupleLists());
        assertEquals(Collections.emptyList(), model.getErrorTupleLists());
    }
}
