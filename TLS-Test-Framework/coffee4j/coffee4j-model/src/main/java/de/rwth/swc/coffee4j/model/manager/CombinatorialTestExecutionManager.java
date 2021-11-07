package de.rwth.swc.coffee4j.model.manager;

import de.rwth.swc.coffee4j.engine.TestResult;
import de.rwth.swc.coffee4j.engine.util.Preconditions;
import de.rwth.swc.coffee4j.model.Combination;
import de.rwth.swc.coffee4j.model.InputParameterModel;
import de.rwth.swc.coffee4j.model.report.ExecutionReporter;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Queue;

/**
 * A class using a {@link CombinatorialTestConsumerManager} internally to manage the complete execution
 * of a combinatorial test via a {@link TestInputExecutor}. This means that after the initial {@link #execute()}
 * method is called, no more method calls are needed and all results are propagated through registered
 * {@link ExecutionReporter} instances.
 */
public class CombinatorialTestExecutionManager {
    
    private final List<ExecutionReporter> executionReporters;
    
    private final TestInputExecutor executor;
    
    private final Queue<Combination> executionQueue = new LinkedList<>();
    
    private final CombinatorialTestConsumerManager generator;

    private final CombinatorialTestConsumerManagerConfiguration configuration;

    /**
     * Creates a new manager with the given configuration, executor and testModel.
     *
     * @param configuration all needed configuration for a combinatorial test. This is the part which can be reused
     *                      *                      across different tests. Must not be {@code null}
     * @param executor      can execute any test inputs possible with the supplied testModel. If the system under test does not
     *                      behave correctly for a given combination, any exception should be thrown.
     *                      This part is generally not reusable. Must not be {@code null}
     * @param model         the testModel which defines all parameters and constraints for a combinatorial test. This part
     *                      is generally not reusable. Must not be {@code null}
     */
    public CombinatorialTestExecutionManager(CombinatorialTestConsumerManagerConfiguration configuration,
                                             TestInputExecutor executor,
                                             InputParameterModel model) {
        Preconditions.notNull(configuration);
        Preconditions.notNull(executor);
        Preconditions.notNull(model);
        
        executionReporters = new ArrayList<>(configuration.getExecutionReporters());
        this.executor = executor;
        this.configuration = configuration;

        generator = new CombinatorialTestConsumerManager(configuration, executionQueue::add, model);
    }
    
    /**
     * Executes a complete combinatorial test including fault characterization (if enabled and configured) using the
     * {@link TestInputExecutor} supplied in the constructor.
     */
    public void execute() {
        if(!diagnoseConstraints()) {
            if(configuration.getConflictDetectionConfiguration().shouldAbort()) {
                System.out.println("Error: conflicts among constraints detected");
                return;
            }
        }

        generator.generateInitialTests();
        
        Combination testInput;
        while ((testInput = executionQueue.poll()) != null) {
            testInputExecutionStarted(testInput);
            final TestResult result = execute(testInput);
            testInputExecutionFinished(testInput, result);
            generator.generateAdditionalTestInputsWithResult(testInput, result);
        }
    }

    private boolean diagnoseConstraints() {
        if(configuration.getConflictDetectionConfiguration().isConflictDetectionEnabled()) {
            return generator.checkConstraintsForConflicts();
        }

        return true;
    }

    private void testInputExecutionStarted(Combination testInput) {
        for (ExecutionReporter reporter : executionReporters) {
            reporter.testInputExecutionStarted(testInput);
        }
    }
    
    private void testInputExecutionFinished(Combination testInput, TestResult result) {
        for (ExecutionReporter reporter : executionReporters) {
            reporter.testInputExecutionFinished(testInput, result);
        }
    }
    
    private TestResult execute(Combination testInput) {
        try {
            executor.execute(testInput);
            return TestResult.success();
        } catch (Throwable e) {
            return TestResult.failure(e);
        }
    }
}
