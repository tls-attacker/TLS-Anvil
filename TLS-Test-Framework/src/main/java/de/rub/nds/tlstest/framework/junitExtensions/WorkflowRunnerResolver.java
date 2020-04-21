package de.rub.nds.tlstest.framework.junitExtensions;

import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.WorkflowRunner;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.ParameterContext;
import org.junit.jupiter.api.extension.ParameterResolutionException;
import org.junit.jupiter.api.extension.ParameterResolver;

import java.lang.reflect.Method;
import java.util.Optional;

public class WorkflowRunnerResolver implements ParameterResolver {

    @Override
    public boolean supportsParameter(ParameterContext parameterContext, ExtensionContext extensionContext) throws ParameterResolutionException {
        return parameterContext.getParameter().getType().equals(WorkflowRunner.class);
    }

    @Override
    public Object resolveParameter(ParameterContext parameterContext, ExtensionContext extensionContext) throws ParameterResolutionException {
        WorkflowRunner param = new WorkflowRunner(TestContext.getInstance());
        Optional<Method> method = extensionContext.getTestMethod();
        if (!method.isPresent()) return param;

        Method testM = method.get();
        if (testM.isAnnotationPresent(KeyExchange.class)) {
            KeyExchange annotation = KeyExchangeType.resolveKexAnnotation(extensionContext);
            param.setKeyExchange(annotation);
        }

        return param;
    }
}
