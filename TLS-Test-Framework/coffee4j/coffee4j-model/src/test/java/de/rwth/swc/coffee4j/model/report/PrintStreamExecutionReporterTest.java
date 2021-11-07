package de.rwth.swc.coffee4j.model.report;

import de.rwth.swc.coffee4j.engine.TestResult;
import de.rwth.swc.coffee4j.engine.characterization.FaultCharacterizationAlgorithm;
import de.rwth.swc.coffee4j.engine.generator.TestInputGroupGenerator;
import de.rwth.swc.coffee4j.engine.report.ReportLevel;
import de.rwth.swc.coffee4j.model.Combination;
import de.rwth.swc.coffee4j.model.Parameter;
import de.rwth.swc.coffee4j.model.TestInputGroupContext;
import de.rwth.swc.coffee4j.model.Value;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;

import java.io.PrintStream;
import java.util.Collections;

import static de.rwth.swc.coffee4j.engine.report.Report.report;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

class PrintStreamExecutionReporterTest {
    
    private static final Combination TEST_INPUT = Combination.combination().value(Parameter.parameter("param1").values(0, 1).build(), Value.value(0, 0)).build();
    
    private static final TestInputGroupContext CONTEXT = new TestInputGroupContext(0, Mockito.mock(TestInputGroupGenerator.class));
    
    private static final FaultCharacterizationAlgorithm ALGORITHM = Mockito.mock(FaultCharacterizationAlgorithm.class);
    
    @Test
    void doesNotThrowAnExceptionIfPassedNull() {
        final PrintStreamExecutionReporter executionReporter = new PrintStreamExecutionReporter();
        
        executionReporter.testInputGroupGenerated(null, null);
        executionReporter.testInputGroupFinished(null);
        executionReporter.faultCharacterizationStarted(null, null);
        executionReporter.faultCharacterizationFinished(null, null);
        executionReporter.faultCharacterizationTestInputsGenerated(null, null);
        executionReporter.report(null, null);
    }
    
    @Test
    void printsToPrintStreamWriter() {
        final PrintStream printStream = Mockito.mock(PrintStream.class);
        final PrintStreamExecutionReporter reporter = new PrintStreamExecutionReporter(printStream);
        
        ArgumentCaptor<String> argumentCaptor = ArgumentCaptor.forClass(String.class);
        reporter.report(ReportLevel.ERROR, report("test"));
        verify(printStream, times(1)).println(argumentCaptor.capture());
        assertTrue(argumentCaptor.getValue().contains("ERROR"));
        assertTrue(argumentCaptor.getValue().contains("test"));
        reset(printStream);
        
        argumentCaptor = ArgumentCaptor.forClass(String.class);
        reporter.testInputExecutionStarted(TEST_INPUT);
        verify(printStream, times(1)).println(argumentCaptor.capture());
        assertTrue(argumentCaptor.getValue().contains(TEST_INPUT.toString()));
        reset(printStream);
        
        reporter.testInputExecutionFinished(TEST_INPUT, TestResult.success());
        verify(printStream, times(1)).println(argumentCaptor.capture());
        assertTrue(argumentCaptor.getValue().contains(TEST_INPUT.toString()));
        assertTrue(argumentCaptor.getValue().contains(TestResult.success().toString()));
        reset(printStream);
        
        argumentCaptor = ArgumentCaptor.forClass(String.class);
        reporter.testInputGroupGenerated(CONTEXT, Collections.singletonList(TEST_INPUT));
        verify(printStream, times(1)).println(argumentCaptor.capture());
        assertTrue(argumentCaptor.getValue().contains(CONTEXT.toString()));
        verify(printStream, times(1)).println(TEST_INPUT);
        reset(printStream);
        
        argumentCaptor = ArgumentCaptor.forClass(String.class);
        reporter.testInputGroupFinished(CONTEXT);
        verify(printStream, times(1)).println(argumentCaptor.capture());
        assertTrue(argumentCaptor.getValue().contains(CONTEXT.toString()));
        reset(printStream);
        
        argumentCaptor = ArgumentCaptor.forClass(String.class);
        reporter.faultCharacterizationStarted(CONTEXT, ALGORITHM);
        verify(printStream, times(1)).println(argumentCaptor.capture());
        assertTrue(argumentCaptor.getValue().contains(CONTEXT.toString()));
        assertTrue(argumentCaptor.getValue().contains(ALGORITHM.getClass().getSimpleName()));
        reset(printStream);
        
        argumentCaptor = ArgumentCaptor.forClass(String.class);
        reporter.faultCharacterizationTestInputsGenerated(CONTEXT, Collections.singletonList(TEST_INPUT));
        verify(printStream, times(1)).println(argumentCaptor.capture());
        assertTrue(argumentCaptor.getValue().contains(CONTEXT.toString()));
        verify(printStream, times(1)).println(TEST_INPUT);
        reset(printStream);
        
        argumentCaptor = ArgumentCaptor.forClass(String.class);
        reporter.faultCharacterizationFinished(CONTEXT, Collections.singletonList(TEST_INPUT));
        verify(printStream, times(2)).println(argumentCaptor.capture());
        System.out.println(argumentCaptor.getAllValues());
        assertTrue(argumentCaptor.getAllValues().get(0).contains(CONTEXT.toString()));
        verify(printStream, times(1)).println(TEST_INPUT);
    }
    
}
