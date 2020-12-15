package de.rwth.swc.coffee4j.model;

import de.rwth.swc.coffee4j.engine.generator.TestInputGroupGenerator;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class TestInputGroupContextTest {
    
    private static final TestInputGroupGenerator GENERATOR = Mockito.mock(TestInputGroupGenerator.class);
    
    @Test
    void preconditions() {
        Assertions.assertThrows(NullPointerException.class, () -> new TestInputGroupContext(null, GENERATOR));
        Assertions.assertThrows(NullPointerException.class, () -> new TestInputGroupContext("test", null));
    }
    
    @Test
    void testValues() {
        final TestInputGroupContext context = new TestInputGroupContext("test", GENERATOR);
        assertEquals("test", context.getIdentifier());
        assertEquals(GENERATOR, context.getGenerator());
    }
    
}
