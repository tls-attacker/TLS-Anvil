package de.rwth.swc.coffee4j.engine.report;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ValueArgumentTest {

    @Test
    void preconditions() {
        assertThrows(IllegalArgumentException.class, () -> new ValueArgument(-1, 0));
        assertThrows(IllegalArgumentException.class, () -> new ValueArgument(0, -1));
    }

    @Test
    void argument() {
        final int parameter = 1;
        final int value = 2;
        final ValueArgument firstArgument = new ValueArgument(parameter, value);
        final ValueArgument secondArgument = ValueArgument.value(parameter, value);

        assertEquals(parameter, firstArgument.getParameter());
        assertEquals(value, firstArgument.getValue());
        assertEquals(parameter, secondArgument.getParameter());
        assertEquals(value, secondArgument.getValue());
    }

}
