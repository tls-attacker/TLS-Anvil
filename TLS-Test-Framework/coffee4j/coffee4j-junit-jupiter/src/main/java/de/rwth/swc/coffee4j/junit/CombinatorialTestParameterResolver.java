package de.rwth.swc.coffee4j.junit;

import de.rwth.swc.coffee4j.model.Combination;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.ParameterContext;
import org.junit.jupiter.api.extension.ParameterResolver;

import java.lang.reflect.Executable;
import java.lang.reflect.Method;

/**
 * Handles parameter resolving for parameters in test inputs from a {@link CombinatorialTest}. Mostly this delegates
 * calls to {@link CombinatorialTestMethodContext}.
 * <p>
 * This class is more or less a copy of {@link org.junit.jupiter.params.ParameterizedTestParameterResolver} from the
 * junit-jupiter-params project.
 */
class CombinatorialTestParameterResolver implements ParameterResolver {
    
    private final CombinatorialTestMethodContext methodContext;
    
    private final Combination testInput;
    
    CombinatorialTestParameterResolver(CombinatorialTestMethodContext methodContext, Combination testInput) {
        this.methodContext = methodContext;
        this.testInput = testInput;
    }
    
    @Override
    public boolean supportsParameter(ParameterContext parameterContext, ExtensionContext extensionContext) {
        final Executable declaringExecutable = parameterContext.getDeclaringExecutable();
        final Method testMethod = extensionContext.getTestMethod().orElse(null);
        
        if (!declaringExecutable.equals(testMethod)) {
            return false;
        }
        
        if (methodContext.isAggregator(parameterContext.getIndex())) {
            return true;
        }
        
        if (methodContext.indexOfFirstAggregator() != -1) {
            return parameterContext.getIndex() < methodContext.indexOfFirstAggregator();
        }
        
        return parameterContext.getIndex() < testInput.size();
    }
    
    @Override
    public Object resolveParameter(ParameterContext parameterContext, ExtensionContext extensionContext) {
        return methodContext.resolve(parameterContext, testInput);
    }
    
}
