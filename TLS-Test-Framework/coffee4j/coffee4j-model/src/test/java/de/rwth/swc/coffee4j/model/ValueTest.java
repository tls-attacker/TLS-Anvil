package de.rwth.swc.coffee4j.model;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNull;

class ValueTest {
    
    @Test
    void dataCanBeNull() {
        final Value value = new Value(0, null);
        
        assertNull(value.get());
    }
    
}
