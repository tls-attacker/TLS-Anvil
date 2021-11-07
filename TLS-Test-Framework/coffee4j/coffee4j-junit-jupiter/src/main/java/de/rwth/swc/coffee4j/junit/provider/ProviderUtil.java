package de.rwth.swc.coffee4j.junit.provider;

import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.platform.commons.JUnitException;
import org.junit.platform.commons.util.Preconditions;
import org.junit.platform.commons.util.ReflectionUtils;
import org.junit.platform.commons.util.StringUtils;

import java.lang.reflect.Method;

/**
 * Utilities used in the provider package.
 */
public final class ProviderUtil {
    
    private ProviderUtil() {
    }
    
    /**
     * Attempts to load the object returned by the method which is defined through the given name.
     * The method is identified using {@link #getMethod(Class, String)}, and reflection is used
     * to invoke it.
     *
     * @param extensionContext the context of the tested method. Must not be {@code null}
     * @param methodName       the name of the method which should be returned. Must not be {@code null}
     * @return the object returned by the defined method
     */
    public static Object getObjectReturnedByMethod(ExtensionContext extensionContext, String methodName) {
        Preconditions.notNull(extensionContext, "Context cannot be null");
        Preconditions.notNull(methodName, "methodName cannot be null");
        
        final Object testInstance = extensionContext.getTestInstance().orElse(null);
        final Method method = getMethod(extensionContext, methodName);
        return ReflectionUtils.invokeMethod(method, testInstance);
    }
    
    /**
     * Attempts to find the method defined by the given name.
     * If the methodName is blank, a method in the test class with the same name as the test method is returned.
     * Otherwise, either the method with the given name in the test class (if the methodName is not fully qualified)
     * or the method in another class (if the method name is fully qualified) is returned.
     * To fully qualify a method name, put the class name before the method name and separate them with a"#".
     *
     * @param context    the context of the tested method. Must not be {@code null}
     * @param methodName the name of the method which should be returned. Must not be {@code null}
     * @return the method defined by the name with the rules explained above
     */
    private static Method getMethod(ExtensionContext context, String methodName) {
        Preconditions.notNull(context, "Context cannot be null");
        Preconditions.notNull(methodName, "methodName cannot be null");
        
        if (StringUtils.isNotBlank(methodName)) {
            if (methodName.contains("#")) {
                return getMethodByFullyQualifiedName(methodName);
            } else {
                return getMethod(context.getRequiredTestClass(), methodName);
            }
        }
        return getMethod(context.getRequiredTestClass(), context.getRequiredTestMethod().getName());
    }
    
    private static Method getMethodByFullyQualifiedName(String fullyQualifiedMethodName) {
        final String[] methodParts = ReflectionUtils.parseFullyQualifiedMethodName(fullyQualifiedMethodName);
        final String className = methodParts[0];
        final String unqualifiedMethodName = methodParts[1];
        final String parameters = methodParts[2];
        
        Preconditions.condition(StringUtils.isBlank(parameters), () -> String.format("factory method [%s] must not declare formal parameters", fullyQualifiedMethodName));
        
        return getMethod(loadRequiredClass(className), unqualifiedMethodName);
    }
    
    private static Class<?> loadRequiredClass(String className) {
        return ReflectionUtils.loadClass(className).orElseThrow(() -> new JUnitException("Could not load class " + className));
    }
    
    private static Method getMethod(Class<?> clazz, String methodName) {
        return ReflectionUtils.findMethod(clazz, methodName).orElseThrow(() -> new JUnitException(String.format("Could not find factory method [%s] in class [%s]", methodName, clazz.getName())));
    }
    
}
