package de.rub.nds.tlstest.framework.junitExtensions;

import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.constants.KeyX;
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
            KeyExchange annotation = KeyX.resolveKexAnnotation(extensionContext);
            param.setKeyExchange(new KeyX(annotation));
        }

        if (testM.isAnnotationPresent(TlsTest.class)) {
            TlsTest annotation = testM.getAnnotation(TlsTest.class);
            param.setTestDescription(annotation.description());
        }

        param.setTestMethodName(testM.getName());

        return param;
    }
}
