package de.rwth.swc.coffee4j.model.manager;

import de.rwth.swc.coffee4j.engine.TestResult;
import de.rwth.swc.coffee4j.engine.characterization.FaultCharacterizationAlgorithm;
import de.rwth.swc.coffee4j.engine.report.Report;
import de.rwth.swc.coffee4j.engine.report.ReportLevel;
import de.rwth.swc.coffee4j.engine.util.Preconditions;
import de.rwth.swc.coffee4j.model.Combination;
import de.rwth.swc.coffee4j.model.TestInputGroupContext;
import de.rwth.swc.coffee4j.model.report.ExecutionReporter;

import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

class DelegatingExecutionReporter implements ExecutionReporter {
    
    private final Set<ExecutionReporter> executionReporters;
    
    DelegatingExecutionReporter(Collection<ExecutionReporter> executionReporters) {
        Preconditions.notNull(executionReporters);
        Preconditions.check(!executionReporters.contains(null));
        
        this.executionReporters = new HashSet<>(executionReporters);
    }
    
    @Override
    public ReportLevel getReportLevel() {
        ReportLevel leastWorstLevel = ReportLevel.FATAL;
        
        for (ExecutionReporter executionReporter : executionReporters) {
            if (!executionReporter.getReportLevel().isWorseThanOrEqualTo(leastWorstLevel)) {
                leastWorstLevel = executionReporter.getReportLevel();
            }
        }
        
        return leastWorstLevel;
    }
    
    @Override
    public void testInputGroupGenerated(TestInputGroupContext context, List<Combination> testInputs) {
        for (ExecutionReporter executionReporter : executionReporters) {
            executionReporter.testInputGroupGenerated(context, testInputs);
        }
    }
    
    @Override
    public void testInputGroupFinished(TestInputGroupContext context) {
        for (ExecutionReporter executionReporter : executionReporters) {
            executionReporter.testInputGroupFinished(context);
        }
    }
    
    @Override
    public void faultCharacterizationStarted(TestInputGroupContext context, FaultCharacterizationAlgorithm algorithm) {
        for (ExecutionReporter executionReporter : executionReporters) {
            executionReporter.faultCharacterizationStarted(context, algorithm);
        }
    }
    
    @Override
    public void faultCharacterizationFinished(TestInputGroupContext context, List<Combination> failureInducingCombinations) {
        for (ExecutionReporter executionReporter : executionReporters) {
            executionReporter.faultCharacterizationFinished(context, failureInducingCombinations);
        }
    }
    
    @Override
    public void faultCharacterizationTestInputsGenerated(TestInputGroupContext context, List<Combination> testInputs) {
        for (ExecutionReporter executionReporter : executionReporters) {
            executionReporter.faultCharacterizationTestInputsGenerated(context, testInputs);
        }
    }
    
    @Override
    public void testInputExecutionStarted(Combination testInput) {
        for (ExecutionReporter executionReporter : executionReporters) {
            executionReporter.testInputExecutionStarted(testInput);
        }
    }
    
    @Override
    public void testInputExecutionFinished(Combination testInput, TestResult result) {
        for (ExecutionReporter executionReporter : executionReporters) {
            executionReporter.testInputExecutionFinished(testInput, result);
        }
    }
    
    @Override
    public void report(ReportLevel level, Report report) {
        Preconditions.notNull(level);
        
        for (ExecutionReporter executionReporter : executionReporters) {
            if (level.isWorseThanOrEqualTo(executionReporter.getReportLevel())) {
                executionReporter.report(level, new Report(report));
            }
        }
    }
}
