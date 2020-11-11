/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlstest.framework.coffee4j;

import de.rwth.swc.coffee4j.engine.TestResult;
import de.rwth.swc.coffee4j.engine.characterization.FaultCharacterizationAlgorithm;
import de.rwth.swc.coffee4j.engine.report.Report;
import de.rwth.swc.coffee4j.engine.report.ReportLevel;
import de.rwth.swc.coffee4j.engine.util.Preconditions;
import de.rwth.swc.coffee4j.model.Combination;
import de.rwth.swc.coffee4j.model.TestInputGroupContext;
import de.rwth.swc.coffee4j.model.report.ExecutionReporter;
import java.io.PrintStream;
import java.util.List;

/**
 *
 * @author marcel
 */
public class TlsTestsuiteReporter implements ExecutionReporter {
    private final PrintStream printStream;
    
    public TlsTestsuiteReporter() {
        printStream = System.out;
    }
    
    @Override
    public void testInputGroupGenerated(TestInputGroupContext context, List<Combination> testInputs) {
        printStream.println("Inputs generated for " + context);
        printStream.println("Test scope consists of " + testInputs.size() + " parameter combinations");
        printStream.println("");
        /*if (testInputs != null) {
            for (Combination testInput : testInputs) {
                printStream.println(testInput.);
            }
        }*/
    }
    
    @Override
    public void testInputGroupFinished(TestInputGroupContext context) {
        printStream.println("All tests completed for" + context);
    }
    
    @Override
    public void faultCharacterizationStarted(TestInputGroupContext context, FaultCharacterizationAlgorithm algorithm) {
        final String algorithmName = algorithm == null ? "null" : algorithm.getClass().getSimpleName();
        printStream.println("Characterization for Test Errors commencing");
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
        //printStream.println("Test input execution started for " + testInput);
    }
    
    @Override
    public void testInputExecutionFinished(Combination testInput, TestResult result) {
        //printStream.println("Test input execution finished for " + testInput + " with result " + result);
    }
    
    @Override
    public void report(ReportLevel level, Report report) {
        printStream.println("Report with level " + level + ": " + report);
    }
}
