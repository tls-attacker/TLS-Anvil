package de.rwth.swc.coffee4j.model.report;

import de.rwth.swc.coffee4j.engine.report.CombinationArgument;
import de.rwth.swc.coffee4j.model.Combination;
import de.rwth.swc.coffee4j.model.converter.ModelConverter;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

class CombinationArgumentConverterTest {
    
    @Test
    void canResolveCombinationArgument() {
        final CombinationArgumentConverter resolver = new CombinationArgumentConverter();
        assertTrue(resolver.canConvert(new CombinationArgument(new int[0])));
    }
    
    @Test
    void cannotResolveNull() {
        final CombinationArgumentConverter resolver = new CombinationArgumentConverter();
        assertFalse(resolver.canConvert(null));
    }
    
    @Test
    void cannotResolveOtherClass() {
        final CombinationArgumentConverter resolver = new CombinationArgumentConverter();
        assertFalse(resolver.canConvert("test"));
    }
    
    @Test
    void resolvesCombination() {
        final Combination resolvedCombination = Combination.combination().build();
        final ModelConverter converter = Mockito.mock(ModelConverter.class);
        when(converter.convertCombination(any(int[].class))).thenReturn(resolvedCombination);
        final int[] combination = new int[0];
        final CombinationArgumentConverter resolver = new CombinationArgumentConverter();
        
        resolver.initialize(converter);
        assertEquals(resolvedCombination, resolver.convert(new CombinationArgument(combination)));
    }
    
}
