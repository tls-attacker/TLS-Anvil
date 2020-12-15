package de.rwth.swc.coffee4j.model;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ParameterTest {
    
    @Test
    void argumentsMayNotBeNull() {
        Assertions.assertThrows(NullPointerException.class, () -> new Parameter(null, Arrays.asList(Value.value(0, 1), Value.value(1, 2))));
        Assertions.assertThrows(NullPointerException.class, () -> new Parameter("test", null));
    }
    
    @Test
    void atLeastTwoValuesRequired() {
        Assertions.assertThrows(IllegalArgumentException.class, () -> new Parameter("a", Collections.emptyList()));
        Assertions.assertThrows(IllegalArgumentException.class, () -> new Parameter("a", Collections.singletonList(Value.value(0, 1))));
        final Parameter twoValueParameter = new Parameter("a", Arrays.asList(Value.value(0, 1), Value.value(1, 2)));
        assertEquals(2, twoValueParameter.size());
    }
    
    @Test
    void cannotContainSameValueIdTwice() {
        Assertions.assertThrows(IllegalArgumentException.class, () -> new Parameter("a", Arrays.asList(Value.value(0, 1), Value.value(0, 2))));
        Assertions.assertThrows(IllegalArgumentException.class, () -> new Parameter("a", Arrays.asList(Value.value(0, 1), Value.value(1, 2), Value.value(1, 2))));
        Assertions.assertThrows(IllegalArgumentException.class, () -> new Parameter("a", Arrays.asList(Value.value(3, 1), Value.value(2, 2), Value.value(1, 3), Value.value(2, 2), Value.value(4, 4))));
    }
    
    @Test
    void valueCannotBeNull() {
        Assertions.assertThrows(IllegalArgumentException.class, () -> new Parameter("a", Arrays.asList(null, null)));
        Assertions.assertThrows(IllegalArgumentException.class, () -> new Parameter("a", Arrays.asList(Value.value(0, 1), null, Value.value(2, 2))));
    }
    
    @Test
    void builderTest() {
        final Parameter parameter = Parameter.parameter("a").value(1).values(2, 3, 4).value(6).values(8, 9).build();
        assertEquals("a", parameter.getName());
        assertEquals(7, parameter.size());
        Assertions.assertEquals(Value.value(0, 1), parameter.getValues().get(0));
        Assertions.assertEquals(Value.value(1, 2), parameter.getValues().get(1));
        Assertions.assertEquals(Value.value(2, 3), parameter.getValues().get(2));
        Assertions.assertEquals(Value.value(3, 4), parameter.getValues().get(3));
        Assertions.assertEquals(Value.value(4, 6), parameter.getValues().get(4));
        Assertions.assertEquals(Value.value(5, 8), parameter.getValues().get(5));
        Assertions.assertEquals(Value.value(6, 9), parameter.getValues().get(6));
        
    }
    
}
