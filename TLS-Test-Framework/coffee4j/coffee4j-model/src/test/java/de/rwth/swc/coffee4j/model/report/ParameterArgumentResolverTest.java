package de.rwth.swc.coffee4j.model.report;

import de.rwth.swc.coffee4j.engine.report.ParameterArgument;
import de.rwth.swc.coffee4j.model.Parameter;
import de.rwth.swc.coffee4j.model.converter.ModelConverter;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.when;

class ParameterArgumentResolverTest {
    
    @Test
    void canConvertParameterArgument() {
        final ParameterArgumentConverter converter = new ParameterArgumentConverter();
        assertTrue(converter.canConvert(new ParameterArgument(0)));
    }
    
    @Test
    void cannotConvertNull() {
        final ParameterArgumentConverter converter = new ParameterArgumentConverter();
        assertFalse(converter.canConvert(null));
    }
    
    @Test
    void cannotConvertOtherClass() {
        final ParameterArgumentConverter converter = new ParameterArgumentConverter();
        assertFalse(converter.canConvert("test"));
    }
    
    @Test
    void convertParameters() {
        final Parameter resolvedParameter = Parameter.parameter("test").values(0, 1).build();
        final ModelConverter modelConverter = Mockito.mock(ModelConverter.class);
        when(modelConverter.convertParameter(anyInt())).thenReturn(resolvedParameter);
        final ParameterArgumentConverter converter = new ParameterArgumentConverter();
        
        converter.initialize(modelConverter);
        assertEquals(resolvedParameter, converter.convert(new ParameterArgument(0)));
    }
    
}
