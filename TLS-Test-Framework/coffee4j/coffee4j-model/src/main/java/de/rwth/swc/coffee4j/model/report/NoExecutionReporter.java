package de.rwth.swc.coffee4j.model.report;

import de.rwth.swc.coffee4j.engine.TestResult;
import de.rwth.swc.coffee4j.engine.characterization.FaultCharacterizationAlgorithm;
import de.rwth.swc.coffee4j.engine.report.Report;
import de.rwth.swc.coffee4j.engine.report.ReportLevel;
import de.rwth.swc.coffee4j.model.Combination;
import de.rwth.swc.coffee4j.model.TestInputGroupContext;

import java.util.List;

/**
 * An example implementation of a {@link ExecutionReporter}. Will print nothing!
 */
public class NoExecutionReporter implements ExecutionReporter {

    /**
     * Creates a new reporter printing no events.
     */
    public NoExecutionReporter() { }

    @Override
    public void testInputGroupGenerated(TestInputGroupContext context, List<Combination> testInputs) { }
    
    @Override
    public void testInputGroupFinished(TestInputGroupContext context) { }
    
    @Override
    public void faultCharacterizationStarted(TestInputGroupContext context, FaultCharacterizationAlgorithm algorithm) { }
    
    @Override
    public void faultCharacterizationFinished(TestInputGroupContext context, List<Combination> failureInducingCombinations) { }
    
    @Override
    public void faultCharacterizationTestInputsGenerated(TestInputGroupContext context, List<Combination> testInputs) { }
    
    @Override
    public void testInputExecutionStarted(Combination testInput) { }
    
    @Override
    public void testInputExecutionFinished(Combination testInput, TestResult result) { }
    
    @Override
    public void report(ReportLevel level, Report report) { }
}
