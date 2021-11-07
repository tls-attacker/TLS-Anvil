package de.rwth.swc.coffee4j.engine.report;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;

import java.text.MessageFormat;
import java.util.function.BiFunction;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class ReportTest {
    
    @Test
    void preconditions() {
        assertThrows(NullPointerException.class, () -> new Report(null, MessageFormat::format));
        assertThrows(NullPointerException.class, () -> new Report("", null));
        assertThrows(NullPointerException.class, () -> new Report("", MessageFormat::format, (Object[]) null));
    }
    
    @Test
    @SuppressWarnings("unchecked")
    void reportResolver() {
        final BiFunction<String, Object[], String> reportResolver = Mockito.mock(BiFunction.class);
        final String message = "test";
        final Object[] arguments = new Object[]{"test1", "test2"};
        final Report report = new Report(message, reportResolver, arguments);
        
        when(reportResolver.apply(any(), any())).thenReturn("resolved");
        assertEquals("resolved", report.getResolvedReport());
        
        final ArgumentCaptor<String> messageCaptor = ArgumentCaptor.forClass(String.class);
        final ArgumentCaptor<Object[]> argumentsCaptor = ArgumentCaptor.forClass(Object[].class);
        
        verify(reportResolver, times(1)).apply(messageCaptor.capture(), argumentsCaptor.capture());
        
        assertEquals(message, messageCaptor.getValue());
        assertEquals(message, report.getResolvableReport());
        assertArrayEquals(arguments, argumentsCaptor.getValue());
    }
    
    @Test
    void argumentConversion() {
        final Report report = Report.report("test", "arg1", "arg2", "arg3");
        final ArgumentConverter firstConverter = Mockito.mock(ArgumentConverter.class);
        final ArgumentConverter secondConverter = Mockito.mock(ArgumentConverter.class);
        
        when(firstConverter.canConvert("arg1")).thenReturn(true);
        when(firstConverter.canConvert("arg2")).thenReturn(false);
        when(firstConverter.canConvert("arg3")).thenReturn(false);
        when(secondConverter.canConvert("arg1")).thenReturn(false);
        when(secondConverter.canConvert("arg2")).thenReturn(true);
        when(secondConverter.canConvert("arg3")).thenReturn(false);
        when(firstConverter.convert("arg1")).thenReturn("arg1Converted");
        when(secondConverter.convert("arg2")).thenReturn("arg2Converted");
        
        assertArrayEquals(new Object[]{"arg1", "arg2", "arg3"}, report.getArguments());
        report.convertArguments(firstConverter);
        assertArrayEquals(new Object[]{"arg1Converted", "arg2", "arg3"}, report.getArguments());
        report.convertArguments(secondConverter);
        assertArrayEquals(new Object[]{"arg1Converted", "arg2Converted", "arg3"}, report.getArguments());
        
        verify(firstConverter, times(1)).convert(any());
        verify(secondConverter, times(1)).convert(any());
        
    }
    
}
