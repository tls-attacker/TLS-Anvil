package de.rwth.swc.coffee4j.model.manager;

import de.rwth.swc.coffee4j.model.converter.ModelConverter;
import de.rwth.swc.coffee4j.model.report.ModelBasedArgumentConverter;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.util.Arrays;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class DelegatingModelBasedArgumentConverterTest {
    
    @Test
    void preconditions() {
        Assertions.assertThrows(NullPointerException.class, () -> new DelegatingModelBasedArgumentConverter(null));
        Assertions.assertThrows(IllegalArgumentException.class, () -> new DelegatingExecutionReporter(Collections.singleton(null)));
    }
    
    @Test
    void initializationIsDelegatedToAllConverters() {
        final ModelBasedArgumentConverter first = Mockito.mock(ModelBasedArgumentConverter.class);
        final ModelBasedArgumentConverter second = Mockito.mock(ModelBasedArgumentConverter.class);
        final DelegatingModelBasedArgumentConverter delegatingConverter = new DelegatingModelBasedArgumentConverter(Arrays.asList(first, second));
        
        final ModelConverter converter = Mockito.mock(ModelConverter.class);
        delegatingConverter.initialize(converter);
        
        verify(first, times(1)).initialize(converter);
        verify(second, times(1)).initialize(converter);
    }
    
    @Test
    void canConvertReturnsTrueIfOneConverterCanConvert() {
        final ModelBasedArgumentConverter first = Mockito.mock(ModelBasedArgumentConverter.class);
        final ModelBasedArgumentConverter second = Mockito.mock(ModelBasedArgumentConverter.class);
        final DelegatingModelBasedArgumentConverter delegatingConverter = new DelegatingModelBasedArgumentConverter(Arrays.asList(first, second));
        
        when(first.canConvert(any())).thenReturn(true);
        when(second.canConvert(any())).thenReturn(false);
        assertTrue(delegatingConverter.canConvert("test"));
        
        when(first.canConvert(any())).thenReturn(false);
        when(second.canConvert(any())).thenReturn(true);
        assertTrue(delegatingConverter.canConvert("test"));
        
        when(first.canConvert(any())).thenReturn(false);
        when(second.canConvert(any())).thenReturn(false);
        assertFalse(delegatingConverter.canConvert("test"));
        
        when(first.canConvert(any())).thenReturn(true);
        when(second.canConvert(any())).thenReturn(true);
        assertTrue(delegatingConverter.canConvert("test"));
    }
    
    @Test
    void exceptionIsThrownIfNoConverterCanConvert() {
        final ModelBasedArgumentConverter first = Mockito.mock(ModelBasedArgumentConverter.class);
        final DelegatingModelBasedArgumentConverter delegatingConverter = new DelegatingModelBasedArgumentConverter(Collections.singletonList(first));
        
        when(first.canConvert(any())).thenReturn(false);
        Assertions.assertThrows(IllegalStateException.class, () -> delegatingConverter.convert("test"));
    }
    
    @Test
    void firstConversionIsReturned() {
        final ModelBasedArgumentConverter first = Mockito.mock(ModelBasedArgumentConverter.class);
        final ModelBasedArgumentConverter second = Mockito.mock(ModelBasedArgumentConverter.class);
        final DelegatingModelBasedArgumentConverter delegatingConverter = new DelegatingModelBasedArgumentConverter(Arrays.asList(first, second));
        
        when(first.canConvert(any())).thenReturn(true);
        when(second.canConvert(any())).thenReturn(true);
        when(first.convert(any())).thenReturn("test");
        assertEquals("test", delegatingConverter.convert("hello"));
        
        when(first.canConvert(any())).thenReturn(false);
        when(second.canConvert(any())).thenReturn(true);
        when(second.convert(any())).thenReturn("test2");
        assertEquals("test2", delegatingConverter.convert("hello"));
    }
    
}
