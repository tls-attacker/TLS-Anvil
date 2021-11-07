package de.rwth.swc.coffee4j.model.report;

import org.junit.jupiter.api.Test;

class ExecutionReporterTest {
    
    @Test
    void doesNotThrowAnExceptionIfPassedNull() {
        final ExecutionReporter executionReporter = new ExecutionReporter() {
        };
        
        executionReporter.testInputGroupGenerated(null, null);
        executionReporter.testInputGroupFinished(null);
        executionReporter.faultCharacterizationStarted(null, null);
        executionReporter.faultCharacterizationFinished(null, null);
        executionReporter.faultCharacterizationTestInputsGenerated(null, null);
        executionReporter.testInputExecutionStarted(null);
        executionReporter.testInputExecutionFinished(null, null);
        executionReporter.report(null, null);
    }
    
}
