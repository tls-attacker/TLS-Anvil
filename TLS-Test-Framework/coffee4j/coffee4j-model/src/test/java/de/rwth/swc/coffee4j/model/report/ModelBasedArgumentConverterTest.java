package de.rwth.swc.coffee4j.model.report;

import de.rwth.swc.coffee4j.model.converter.ModelConverter;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ModelBasedArgumentConverterTest {
    
    private static final ModelBasedArgumentConverter CONVERTER = new ModelBasedArgumentConverter() {
        @Override
        public boolean canConvert(Object argument) {
            return false;
        }
        
        @Override
        public Object convert(Object argument) {
            return null;
        }
    };
    
    @Test
    void converterCannotBeNull() {
        assertThrows(NullPointerException.class, () -> CONVERTER.initialize(null));
    }
    
    @Test
    void initializationWorksCorrectly() {
        final ModelConverter converter = Mockito.mock(ModelConverter.class);
        CONVERTER.initialize(converter);
        assertEquals(converter, CONVERTER.modelConverter);
    }
    
}
