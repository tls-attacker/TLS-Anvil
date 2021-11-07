package de.rwth.swc.coffee4j.model.manager;

import de.rwth.swc.coffee4j.engine.TestResult;
import de.rwth.swc.coffee4j.engine.characterization.FaultCharacterizationAlgorithm;
import de.rwth.swc.coffee4j.engine.generator.TestInputGroupGenerator;
import de.rwth.swc.coffee4j.engine.report.Report;
import de.rwth.swc.coffee4j.engine.report.ReportLevel;
import de.rwth.swc.coffee4j.model.Combination;
import de.rwth.swc.coffee4j.model.TestInputGroupContext;
import de.rwth.swc.coffee4j.model.report.ExecutionReporter;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;

import static de.rwth.swc.coffee4j.engine.report.Report.report;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

class DelegatingExecutionReporterTest {
    
    @Test
    void preconditions() {
        Assertions.assertThrows(NullPointerException.class, () -> new DelegatingExecutionReporter(null));
        Assertions.assertThrows(IllegalArgumentException.class, () -> new DelegatingExecutionReporter(Collections.singleton(null)));
    }
    
    @Test
    void reportLevelIsAlwaysLowestLevelOfChildReporters() {
        final ExecutionReporter first = Mockito.mock(ExecutionReporter.class);
        final ExecutionReporter second = Mockito.mock(ExecutionReporter.class);
        
        final DelegatingExecutionReporter reporter = new DelegatingExecutionReporter(Arrays.asList(first, second));
        
        when(first.getReportLevel()).thenReturn(ReportLevel.TRACE);
        when(second.getReportLevel()).thenReturn(ReportLevel.DEBUG);
        assertEquals(ReportLevel.TRACE, reporter.getReportLevel());
        
        when(first.getReportLevel()).thenReturn(ReportLevel.FATAL);
        when(second.getReportLevel()).thenReturn(ReportLevel.INFO);
        assertEquals(ReportLevel.INFO, reporter.getReportLevel());
    }
    
    @Test
    void testDelegationOfLifecycleMethods() {
        final TestInputGroupGenerator generator = Mockito.mock(TestInputGroupGenerator.class);
        final TestInputGroupContext context = new TestInputGroupContext("test", generator);
        final Combination testInput = new Combination(new HashMap<>());
        final List<Combination> testInputs = Collections.singletonList(testInput);
        final FaultCharacterizationAlgorithm algorithm = Mockito.mock(FaultCharacterizationAlgorithm.class);
        final TestResult testResult = TestResult.failure(new IllegalArgumentException("test"));
        
        final ExecutionReporter first = Mockito.mock(ExecutionReporter.class);
        final ExecutionReporter second = Mockito.mock(ExecutionReporter.class);
        final DelegatingExecutionReporter reporter = new DelegatingExecutionReporter(Arrays.asList(first, second));
        
        reporter.testInputGroupGenerated(context, testInputs);
        verify(first, times(1)).testInputGroupGenerated(context, testInputs);
        verify(second, times(1)).testInputGroupGenerated(context, testInputs);
        
        reporter.testInputGroupFinished(context);
        verify(first, times(1)).testInputGroupFinished(context);
        verify(second, times(1)).testInputGroupFinished(context);
        
        reporter.faultCharacterizationStarted(context, algorithm);
        verify(first, times(1)).faultCharacterizationStarted(context, algorithm);
        verify(second, times(1)).faultCharacterizationStarted(context, algorithm);
        
        reporter.faultCharacterizationFinished(context, testInputs);
        verify(first, times(1)).faultCharacterizationFinished(context, testInputs);
        verify(second, times(1)).faultCharacterizationFinished(context, testInputs);
        
        reporter.faultCharacterizationTestInputsGenerated(context, testInputs);
        verify(first, times(1)).faultCharacterizationTestInputsGenerated(context, testInputs);
        verify(second, times(1)).faultCharacterizationTestInputsGenerated(context, testInputs);
        
        reporter.testInputExecutionStarted(testInput);
        verify(first, times(1)).testInputExecutionStarted(testInput);
        verify(second, times(1)).testInputExecutionStarted(testInput);
        
        reporter.testInputExecutionFinished(testInput, testResult);
        verify(first, times(1)).testInputExecutionFinished(testInput, testResult);
        verify(second, times(1)).testInputExecutionFinished(testInput, testResult);
        
        verifyNoMoreInteractions(first);
        verifyNoMoreInteractions(second);
    }
    
    @Test
    void reportsOnlyDelegatedWhenLevelHighEnough() {
        final ExecutionReporter first = Mockito.mock(ExecutionReporter.class);
        final ExecutionReporter second = Mockito.mock(ExecutionReporter.class);
        final DelegatingExecutionReporter reporter = new DelegatingExecutionReporter(Arrays.asList(first, second));
        when(first.getReportLevel()).thenReturn(ReportLevel.FATAL);
        when(second.getReportLevel()).thenReturn(ReportLevel.INFO);
        
        final Report report = report("test");
        reporter.report(ReportLevel.DEBUG, report);
        verify(first, never()).report(any(), any());
        verify(second, never()).report(any(), any());
        
        reporter.report(ReportLevel.INFO, report);
        verify(second, times(1)).report(ReportLevel.INFO, report);
        verify(first, never()).report(any(), any());
        
        reporter.report(ReportLevel.FATAL, report);
        verify(first, times(1)).report(ReportLevel.FATAL, report);
        verify(second, times(1)).report(ReportLevel.FATAL, report);
    }
    
}
