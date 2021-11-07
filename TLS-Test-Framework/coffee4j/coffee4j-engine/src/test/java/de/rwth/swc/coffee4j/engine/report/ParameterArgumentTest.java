package de.rwth.swc.coffee4j.engine.report;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ParameterArgumentTest {
    
    @Test
    void preconditions() {
        assertThrows(IllegalArgumentException.class, () -> new ParameterArgument(-1));
        assertThrows(IllegalArgumentException.class, () -> new ParameterArgument(-100));
    }
    
    @Test
    void argument() {
        final int parameter = 0;
        final ParameterArgument firstArgument = new ParameterArgument(parameter);
        final ParameterArgument secondArgument = ParameterArgument.parameter(parameter);
        
        assertEquals(parameter, firstArgument.getParameter());
        assertEquals(parameter, secondArgument.getParameter());
    }
    
}
