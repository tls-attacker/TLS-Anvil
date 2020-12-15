package de.rub.nds.tlstest.framework.coffee4j.junit;

import de.rwth.swc.coffee4j.engine.TestResult;
import de.rwth.swc.coffee4j.model.Combination;
import de.rwth.swc.coffee4j.model.manager.CombinatorialTestConsumerManager;
import de.rwth.swc.coffee4j.model.report.ExecutionReporter;
import org.junit.jupiter.api.extension.AfterTestExecutionCallback;
import org.junit.jupiter.api.extension.BeforeTestExecutionCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

import java.util.List;
import java.util.Optional;

/**
 * Used to call the {@link ExecutionReporter#testInputExecutionStarted(Combination)} and
 * {@link ExecutionReporter#testInputExecutionFinished(Combination, TestResult)} method for registered reporters
 * and generate new test inputs based on test results (for example for fault characterization).
 */
public class CombinatorialTestExecutionCallback implements BeforeTestExecutionCallback, AfterTestExecutionCallback {
    
    static final String MANAGER_KEY = "manager";
    static final String REPORTERS_KEY = "reporter";
    
    private final Combination testInput;
    
    CombinatorialTestExecutionCallback(Combination testInput) {
        this.testInput = testInput;
    }
    
    @Override
    public void beforeTestExecution(ExtensionContext extensionContext) {
        final List<ExecutionReporter> reporters = getRequiredExecutionReporter(extensionContext);
        testInputExecutionStarted(reporters, testInput);
    }
    
    private void testInputExecutionStarted(List<ExecutionReporter> reporters, Combination testInput) {
        for (ExecutionReporter reporter : reporters) {
            reporter.testInputExecutionStarted(testInput);
        }
    }
    
    @Override
    public void afterTestExecution(ExtensionContext extensionContext) {
        final TestResult result = convertToTestResult(extensionContext);
        final List<ExecutionReporter> reporters = getRequiredExecutionReporter(extensionContext);
        testInputExecutionFinished(reporters, testInput, result);
        
        final CombinatorialTestConsumerManager manager = getRequiredGenerator(extensionContext);
        manager.generateAdditionalTestInputsWithResult(testInput, result);
    }
    
    private void testInputExecutionFinished(List<ExecutionReporter> reporters, Combination testInput, TestResult result) {
        for (ExecutionReporter reporter : reporters) {
            reporter.testInputExecutionFinished(testInput, result);
        }
    }
    
    private CombinatorialTestConsumerManager getRequiredGenerator(ExtensionContext extensionContext) {
        return CombinatorialTestExtension.getStore(extensionContext).get(MANAGER_KEY, CombinatorialTestConsumerManager.class);
    }
    
    @SuppressWarnings("unchecked")
    private List<ExecutionReporter> getRequiredExecutionReporter(ExtensionContext extensionContext) {
        return (List<ExecutionReporter>) CombinatorialTestExtension.getStore(extensionContext).get(REPORTERS_KEY, List.class);
    }
    
    private TestResult convertToTestResult(ExtensionContext extensionContext) {
        final Optional<Throwable> executionException = extensionContext.getExecutionException();
        
        return executionException.map(TestResult::failure).orElseGet(TestResult::success);
    }
    
}
