package de.rub.nds.tlstest.framework;

import de.rub.nds.tlstest.framework.annotations.ClientTest;
import de.rub.nds.tlstest.framework.annotations.ServerTest;
import de.rub.nds.tlstest.framework.constants.TestEndpointType;
import org.junit.jupiter.api.extension.ExtensionContext;

import java.lang.reflect.Method;

public class TestContext {

    private TestEndpointType testEndpointType;

    public TestContext(ExtensionContext context) {

        Method testMethod = context.getRequiredTestMethod();
        Class<?> testClass = context.getRequiredTestClass();

        if (testMethod.isAnnotationPresent(ClientTest.class)) {
            testEndpointType = TestEndpointType.CLIENT;
        } else if (testMethod.isAnnotationPresent(ServerTest.class)) {
            testEndpointType = TestEndpointType.SERVER;
        } else if (testClass.isAnnotationPresent(ClientTest.class)) {
            testEndpointType = TestEndpointType.CLIENT;
        } else if (testClass.isAnnotationPresent(ServerTest.class)) {
            testEndpointType = TestEndpointType.SERVER;
        } else {
            testEndpointType = TestEndpointType.BOTH;
        }
    }

    public TestEndpointType getTestEndpointType() {
        return testEndpointType;
    }
}
