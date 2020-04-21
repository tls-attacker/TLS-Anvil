package de.rub.nds.tlstest.framework.junitExtensions;

import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.annotations.ClientTest;
import de.rub.nds.tlstest.framework.annotations.ServerTest;
import de.rub.nds.tlstest.framework.config.TestConfig;
import de.rub.nds.tlstest.framework.constants.TestEndpointType;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.api.extension.ExtensionContext;

import java.lang.reflect.Method;

public class EndpointCondition extends BaseCondition {

    private TestEndpointType endpointOfMethod(ExtensionContext context) {
        Method testMethod = context.getRequiredTestMethod();
        Class<?> testClass = context.getRequiredTestClass();

        if (testMethod.isAnnotationPresent(ClientTest.class)) {
            return TestEndpointType.CLIENT;
        } else if (testMethod.isAnnotationPresent(ServerTest.class)) {
            return TestEndpointType.SERVER;
        } else if (testClass.isAnnotationPresent(ClientTest.class)) {
            return TestEndpointType.CLIENT;
        } else if (testClass.isAnnotationPresent(ServerTest.class)) {
            return TestEndpointType.SERVER;
        } else {
            return TestEndpointType.BOTH;
        }
    }

    @Override
    public ConditionEvaluationResult evaluateExecutionCondition(ExtensionContext context) {
        if (!context.getTestMethod().isPresent()) {
            return ConditionEvaluationResult.enabled("Class annotations are not relevant.");
        }

        TestConfig config = TestContext.getInstance().getConfig();

        if (endpointOfMethod(context) == config.getTestEndpointMode() || endpointOfMethod(context) == TestEndpointType.BOTH) {
            return ConditionEvaluationResult.enabled("TestEndpointMode matches");
        }

        return ConditionEvaluationResult.disabled("TestEndpointMode doesn't match, skipping test.");
    }
}
