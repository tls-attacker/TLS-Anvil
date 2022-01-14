/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.junitExtensions;

import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.annotations.ClientTest;
import de.rub.nds.tlstest.framework.annotations.ServerTest;
import de.rub.nds.tlstest.framework.annotations.TestEndpoint;
import de.rub.nds.tlstest.framework.config.TestConfig;
import de.rub.nds.tlstest.framework.constants.TestEndpointType;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.api.extension.ExtensionContext;

import java.lang.reflect.Method;

/**
 * Evaluates the ClientTest, ServerTest, TestEndpoint annotations
 * The test is disabled when a client is tested but the test is written for servers.
 */
public class EndpointCondition extends BaseCondition {

    private TestEndpointType endpointOfMethod(ExtensionContext context) {
        Method testMethod = context.getRequiredTestMethod();
        Class<?> testClass = context.getRequiredTestClass();

        return endpointOfMethod(testMethod, testClass);
    }
    
    public static TestEndpointType endpointOfMethod(Method testMethod, Class<?> testClass) {
        if (testMethod.isAnnotationPresent(ClientTest.class)) {
            return TestEndpointType.CLIENT;
        } else if (testMethod.isAnnotationPresent(ServerTest.class)) {
            return TestEndpointType.SERVER;
        } else if (testClass.isAnnotationPresent(ClientTest.class)) {
            return TestEndpointType.CLIENT;
        } else if (testClass.isAnnotationPresent(ServerTest.class)) {
            return TestEndpointType.SERVER;
        } else if (testMethod.isAnnotationPresent(TestEndpoint.class)) {
            return testMethod.getAnnotation(TestEndpoint.class).endpoint();
        } else if (testClass.isAnnotationPresent(TestEndpoint.class)) {
            return testClass.getAnnotation(TestEndpoint.class).endpoint();
        } else {
            return TestEndpointType.BOTH;
        }
    }

    @Override
    public ConditionEvaluationResult evaluateExecutionCondition(ExtensionContext extensionContext) {
        if (!extensionContext.getTestMethod().isPresent()) {
            return ConditionEvaluationResult.enabled("Class annotations are not relevant.");
        }

        TestContext context = TestContext.getInstance();
        TestConfig config = context.getConfig();
        TestEndpointType mode = endpointOfMethod(extensionContext);
        synchronized (TestContext.getInstance()) {
            if (!config.isParsedArgs()) {
                config.setTestEndpointMode(mode);
                config.parse(null);
                context.getTestRunner().prepareTestExecution();
            }
        }

        if (mode == config.getTestEndpointMode() || mode == TestEndpointType.BOTH) {
            return ConditionEvaluationResult.enabled("TestEndpointMode matches");
        }

        return ConditionEvaluationResult.disabled("TestEndpointMode doesn't match, skipping test.");
    }
}
