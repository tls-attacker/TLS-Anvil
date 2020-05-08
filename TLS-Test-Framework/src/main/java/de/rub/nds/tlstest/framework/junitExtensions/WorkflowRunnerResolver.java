package de.rub.nds.tlstest.framework.junitExtensions;

import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.constants.KeyX;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.utils.TestMethodConfig;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.ParameterContext;
import org.junit.jupiter.api.extension.ParameterResolutionException;
import org.junit.jupiter.api.extension.ParameterResolver;

import java.lang.reflect.Method;
import java.util.Optional;

public class WorkflowRunnerResolver implements ParameterResolver {
    private static final Logger LOGGER = LogManager.getLogger();

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
        Class<?> testClass = extensionContext.getRequiredTestClass();

        TestMethodConfig testMethodConfig = new TestMethodConfig();
        param.setTestMethodConfig(testMethodConfig);

        if (testM.isAnnotationPresent(KeyExchange.class)) {
            KeyExchange annotation = KeyX.resolveKexAnnotation(extensionContext);
            testMethodConfig.setKeyExchange(new KeyX(annotation));
        }

        if (testM.isAnnotationPresent(TlsTest.class)) {
            TlsTest annotation = testM.getAnnotation(TlsTest.class);
            testMethodConfig.setTlsTest(annotation);
        }

        if (testM.isAnnotationPresent(RFC.class)) {
            testMethodConfig.setRfc(testM.getAnnotation(RFC.class));
        }
        else if (testClass.isAnnotationPresent(RFC.class)) {
            testMethodConfig.setRfc(testClass.getAnnotation(RFC.class));
        }

        testMethodConfig.setMethodName(testM.getName());
        testMethodConfig.setClassName(testClass.getName());
        testMethodConfig.setDisplayName(extensionContext.getDisplayName());
        param.setExtensionContext(extensionContext);

        return param;
    }
}
