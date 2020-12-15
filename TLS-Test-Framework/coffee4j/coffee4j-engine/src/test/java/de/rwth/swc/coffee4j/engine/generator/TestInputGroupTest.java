package de.rwth.swc.coffee4j.engine.generator;

import de.rwth.swc.coffee4j.engine.characterization.FaultCharacterizationConfiguration;
import de.rwth.swc.coffee4j.engine.report.Reporter;
import de.rwth.swc.coffee4j.engine.TestModel;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.util.Arrays;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TestInputGroupTest {
    
    @Test
    void preconditions() {
        Assertions.assertThrows(NullPointerException.class, () -> new TestInputGroup(null, Collections.emptyList()));
        Assertions.assertThrows(NullPointerException.class, () -> new TestInputGroup(null, Collections.emptyList(), null));
        
        Assertions.assertThrows(NullPointerException.class, () -> new TestInputGroup("", null));
        Assertions.assertThrows(NullPointerException.class, () -> new TestInputGroup("", null, null));
    }
    
    @Test
    void noFaultCharacterizationConfigurationWithSmallConstructorOrNull() {
        assertFalse(new TestInputGroup("", Collections.emptyList(), null).getFaultCharacterizationConfiguration().isPresent());
        assertFalse(new TestInputGroup("", Collections.emptyList()).getFaultCharacterizationConfiguration().isPresent());
    }
    
    @Test
    void correctInformationStorage() {
        final int[] firstCombination = new int[]{0, 1, 2};
        final int[] secondCombination = new int[]{3, 2, 1};
        final FaultCharacterizationConfiguration configuration = new FaultCharacterizationConfiguration(new TestModel(2, new int[]{3, 3, 3}, Collections.emptyList(), Collections.emptyList()), Mockito.mock(Reporter.class));
        final TestInputGroup group = new TestInputGroup("test", Arrays.asList(firstCombination, secondCombination), configuration);
        
        assertEquals(2, group.getTestInputs().size());
        assertArrayEquals(firstCombination, group.getTestInputs().get(0));
        assertArrayEquals(secondCombination, group.getTestInputs().get(1));
        assertEquals("test", group.getIdentifier());
        assertTrue(group.getFaultCharacterizationConfiguration().isPresent());
        assertEquals(configuration, group.getFaultCharacterizationConfiguration().get());
    }
    
}
