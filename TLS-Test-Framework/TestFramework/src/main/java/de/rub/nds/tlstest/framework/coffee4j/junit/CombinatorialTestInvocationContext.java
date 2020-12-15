package de.rub.nds.tlstest.framework.coffee4j.junit;

import de.rwth.swc.coffee4j.model.Combination;
import org.junit.jupiter.api.extension.Extension;
import org.junit.jupiter.api.extension.TestTemplateInvocationContext;

import java.util.Arrays;
import java.util.List;

/**
 * Handles one test input in a combinatorial test and the extensions needed for one test input:
 * {@link CombinatorialTestParameterResolver} and {@link CombinatorialTestExecutionCallback}.
 * <p>
 * This is more or less a copy of {@link org.junit.jupiter.params.ParameterizedTestInvocationContext} from the
 * junit-jupiter-params project.
 */
public class CombinatorialTestInvocationContext implements TestTemplateInvocationContext {
    
    private final CombinatorialTestNameFormatter nameFormatter;
    
    private final CombinatorialTestMethodContext methodContext;
    
    private final Combination testInput;
    
    CombinatorialTestInvocationContext(CombinatorialTestNameFormatter nameFormatter, CombinatorialTestMethodContext methodContext, Combination testInput) {
        this.nameFormatter = nameFormatter;
        this.methodContext = methodContext;
        this.testInput = testInput;
    }
    
    @Override
    public String getDisplayName(int invocationIndex) {
        return nameFormatter.format(invocationIndex, testInput);
    }
    
    @Override
    public List<Extension> getAdditionalExtensions() {
        return Arrays.asList(new CombinatorialTestParameterResolver(methodContext, testInput), new CombinatorialTestExecutionCallback(testInput));
    }
    
}
