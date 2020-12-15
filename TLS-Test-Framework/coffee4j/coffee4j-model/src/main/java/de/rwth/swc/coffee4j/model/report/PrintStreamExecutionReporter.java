package de.rwth.swc.coffee4j.model.report;

import de.rwth.swc.coffee4j.engine.TestResult;
import de.rwth.swc.coffee4j.engine.characterization.FaultCharacterizationAlgorithm;
import de.rwth.swc.coffee4j.engine.report.Report;
import de.rwth.swc.coffee4j.engine.report.ReportLevel;
import de.rwth.swc.coffee4j.engine.util.Preconditions;
import de.rwth.swc.coffee4j.model.Combination;
import de.rwth.swc.coffee4j.model.TestInputGroupContext;

import java.io.PrintStream;
import java.util.List;

/**
 * An example implementation of a {@link ExecutionReporter}. Will print to any {@link PrintStream} or
 * {@link System#out} by default.
 */
public class PrintStreamExecutionReporter implements ExecutionReporter {
    
    private final PrintStream printStream;
    
    /**
     * Creates a new reporter printing all events to {@link System#out}.
     */
    public PrintStreamExecutionReporter() {
        this(System.out);
    }
    
    /**
     * Creates a new reporter printing all events to the given stream.
     *
     * @param printStream the stream to which events are printed. Must not be {@code null}
     */
    public PrintStreamExecutionReporter(PrintStream printStream) {
        this.printStream = Preconditions.notNull(printStream);
    }
    
    @Override
    public void testInputGroupGenerated(TestInputGroupContext context, List<Combination> testInputs) {
        printStream.println("Generated test input group with context \"" + context + "\" and the following test inputs");
        if (testInputs != null) {
            for (Combination testInput : testInputs) {
                printStream.println(testInput);
            }
        }
    }
    
    @Override
    public void testInputGroupFinished(TestInputGroupContext context) {
        printStream.println("Finished generating test inputs for group with context \"" + context + "\"");
    }
    
    @Override
    public void faultCharacterizationStarted(TestInputGroupContext context, FaultCharacterizationAlgorithm algorithm) {
        final String algorithmName = algorithm == null ? "null" : algorithm.getClass().getSimpleName();
        printStream.println("The fault characterization for group with context \"" + context + "\" has started with " + "algorithm " + algorithmName);
    }
    
    @Override
    public void faultCharacterizationFinished(TestInputGroupContext context, List<Combination> failureInducingCombinations) {
        printStream.println("The fault characterization for group with context \"" + context + "\" has finished.");
        if (failureInducingCombinations == null || failureInducingCombinations.isEmpty()) {
            printStream.println("No failure inducing combinations where found");
        } else {
            printStream.println("The following failure inducing combinations where found:");
            
            for (Combination failureInducingCombination : failureInducingCombinations) {
                printStream.println(failureInducingCombination);
            }
        }
    }
    
    @Override
    public void faultCharacterizationTestInputsGenerated(TestInputGroupContext context, List<Combination> testInputs) {
        printStream.println("Additional test inputs where generated for the fault characterization for the group with " + "context \"" + context + "\":");
        if (testInputs != null) {
            for (Combination testInput : testInputs) {
                printStream.println(testInput);
            }
        }
    }
    
    @Override
    public void testInputExecutionStarted(Combination testInput) {
        printStream.println("Test input execution started for " + testInput);
    }
    
    @Override
    public void testInputExecutionFinished(Combination testInput, TestResult result) {
        printStream.println("Test input execution finished for " + testInput + " with result " + result);
    }
    
    @Override
    public void report(ReportLevel level, Report report) {
        printStream.println("Report with level " + level + ": " + report);
    }
}
