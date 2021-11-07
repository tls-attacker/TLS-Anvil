package de.rwth.swc.coffee4j.model;

import de.rwth.swc.coffee4j.engine.util.Preconditions;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.testng.annotations.IParameterizable;

import java.util.HashMap;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class CombinationTest {
    
    @ParameterizedTest
    @MethodSource
    void preconditions(Map<Parameter, Value> parameterValueMap, Class<? extends Exception> expectedException) {
        assertThrows(expectedException, () -> new Combination(parameterValueMap));
    }
    
    private static Stream<Arguments> preconditions() {
        return Stream.of(arguments(null, NullPointerException.class), arguments(nullKeyMap(), IllegalArgumentException.class), arguments(nullValueMap(), IllegalArgumentException.class), arguments(wrongValueMap(), IllegalArgumentException.class));
    }
    
    private static Map<Parameter, Value> nullKeyMap() {
        final Map<Parameter, Value> map = new HashMap<>();
        map.put(null, Value.value(1, 2));
        return map;
    }
    
    private static Map<Parameter, Value> nullValueMap() {
        final Map<Parameter, Value> map = new HashMap<>();
        map.put(Parameter.parameter("test").values(1, 2).build(), null);
        return map;
    }
    
    private static Map<Parameter, Value> wrongValueMap() {
        final Map<Parameter, Value> map = new HashMap<>();
        map.put(Parameter.parameter("test").values(1, 2).build(), Value.value(3, 3));
        return map;
    }
    
    @Test
    void valueAccessMethods() {
        final Parameter firstParameter = Parameter.parameter("param1").values(0, 1).build();
        final Parameter secondParameter = Parameter.parameter("param2").values("one", "two", "three").build();
        final Parameter thirdParameter = Parameter.parameter("param3").values(1.1, 2.2, 3.3, 4.4).build();
        final Parameter fourthParameter = Parameter.parameter("param4").values(1, 2).build();
        final Combination combination = Combination.combination().value(firstParameter, Value.value(0, 0)).value(secondParameter, Value.value(0, "one")).value(thirdParameter, Value.value(3, 4.4)).build();
        
        assertEquals(3, combination.size());
        
        Assertions.assertEquals(Value.value(0, 0), combination.getValue(firstParameter));
        Assertions.assertEquals(Value.value(0, "one"), combination.getValue(secondParameter));
        Assertions.assertEquals(Value.value(3, 4.4), combination.getValue(thirdParameter));
        assertNull(combination.getValue(fourthParameter));
        
        Assertions.assertEquals(Value.value(0, 0), combination.getValue("param1"));
        Assertions.assertEquals(Value.value(0, "one"), combination.getValue("param2"));
        Assertions.assertEquals(Value.value(3, 4.4), combination.getValue("param3"));
        assertNull(combination.getValue("param4"));
        
        assertEquals(0, combination.getRawValue(firstParameter));
        assertEquals("one", combination.getRawValue(secondParameter));
        assertEquals(4.4, combination.getRawValue(thirdParameter));
        assertThrows(IllegalArgumentException.class, () -> combination.getRawValue(fourthParameter));
        
        assertEquals(0, combination.getRawValue("param1"));
        assertEquals("one", combination.getRawValue("param2"));
        assertEquals(4.4, combination.getRawValue("param3"));
        assertThrows(IllegalArgumentException.class, () -> combination.getRawValue("param4"));
    }

    @ParameterizedTest
    @MethodSource
    void containsTests(Combination first, Combination second, boolean shouldContain) {
        assertEquals(shouldContain, first.contains(second));
    }

    private static Stream<Arguments> containsTests() {
        final Parameter a = Parameter.parameter("a").values(1, 2, 3).build();
        final Parameter b = Parameter.parameter("b").values(1, 2, 3).build();
        final Parameter c = Parameter.parameter("c").values(1, 2, 3).build();
        final Parameter d = Parameter.parameter("d").values(1, 2, 3).build();

        return Stream.of(
                arguments(createCombination(new Parameter[] {a, b, c, d}, new int[] {0, 0, 0, 0}),
                          createCombination(new Parameter[] {a, b, c, d}, new int[] {0, 0, 0, 0}),
                          true),
                arguments(createCombination(new Parameter[] {a, b, c, d}, new int[] {0, 0, 0, 0}),
                          createCombination(new Parameter[] {a, b}, new int[] {0, 0}),
                          true),
                arguments(createCombination(new Parameter[] {a, b}, new int[] {0, 0}),
                          createCombination(new Parameter[] {a, b, c, d}, new int[] {0, 0, 0, 0}),
                          false),
                arguments(createCombination(new Parameter[] {a, b, c}, new int[] {0, 0, 0}),
                          createCombination(new Parameter[] {a, b, d}, new int[] {0, 0, 0}),
                          false),
                arguments(createCombination(new Parameter[] {a, b, c, d}, new int[] {0, 0, 0, 0}),
                          createCombination(new Parameter[] {a, b, c, d}, new int[] {1, 0, 0, 0}),
                          false)
        );
    }

    private static Combination createCombination(Parameter[] parameters, int[] valueIndices) {
        Preconditions.check(parameters.length == valueIndices.length);

        final Map<Parameter, Value> map = new HashMap<>();

        for(int i = 0; i < parameters.length; i++) {
            final Parameter parameter = parameters[i];
            final int valueIndex = valueIndices[i];
            final Value value = parameter.getValues().get(valueIndex);

            map.put(parameter, value);
        }

        return new Combination(map);
    }
}
