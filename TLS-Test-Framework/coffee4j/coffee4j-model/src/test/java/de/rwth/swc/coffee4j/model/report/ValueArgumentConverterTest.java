package de.rwth.swc.coffee4j.model.report;

import de.rwth.swc.coffee4j.engine.report.ValueArgument;
import de.rwth.swc.coffee4j.model.Value;
import de.rwth.swc.coffee4j.model.converter.ModelConverter;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.when;

class ValueArgumentConverterTest {
    
    @Test
    void canConvertValueArgument() {
        final ValueArgumentConverter converter = new ValueArgumentConverter();
        assertTrue(converter.canConvert(new ValueArgument(0, 0)));
    }
    
    @Test
    void cannotConvertNull() {
        final ValueArgumentConverter converter = new ValueArgumentConverter();
        assertFalse(converter.canConvert(null));
    }
    
    @Test
    void cannotConvertOtherClass() {
        final ValueArgumentConverter converter = new ValueArgumentConverter();
        assertFalse(converter.canConvert("test"));
    }
    
    @Test
    void convertValue() {
        final Value resolvedValue = Value.value(0, 1);
        final ModelConverter modelConverter = Mockito.mock(ModelConverter.class);
        when(modelConverter.convertValue(anyInt(), anyInt())).thenReturn(resolvedValue);
        final ValueArgumentConverter converter = new ValueArgumentConverter();
        
        converter.initialize(modelConverter);
        assertEquals(resolvedValue, converter.convert(new ValueArgument(0, 0)));
    }
    
}
