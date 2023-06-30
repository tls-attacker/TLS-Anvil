/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * Copyright 2022 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.simpleTest;

import de.rub.nds.tlstest.framework.model.derivationParameter.DerivationParameter;
import java.util.List;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.ParameterContext;
import org.junit.jupiter.api.extension.ParameterResolutionException;
import org.junit.jupiter.api.extension.ParameterResolver;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

/**
 *
 */
public class SimpleTestParameterResolver implements ParameterResolver  {
    
    private final List<DerivationParameter> testInput;

    public SimpleTestParameterResolver(List<DerivationParameter> testInput) {
        this.testInput = testInput;
    }

    @Override
    public boolean supportsParameter(ParameterContext parameterContext, ExtensionContext extensionContext) throws ParameterResolutionException {
        if(parameterContext.getParameter().getType() == ArgumentsAccessor.class) {
            return true;
        }
        return false;
    }

    @Override
    public Object resolveParameter(ParameterContext parameterContext, ExtensionContext extensionContext) throws ParameterResolutionException {
        return new SimpleArgumentsAccessor(testInput);
    }

}
