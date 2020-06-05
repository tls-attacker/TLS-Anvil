package de.rub.nds.tlstest.framework.junitExtensions;

import de.rub.nds.tlstest.framework.annotations.MethodCondition;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.api.extension.ExtensionContext;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Optional;

public class MethodConditionExtension extends BaseCondition {
    private static final Logger LOGGER = LogManager.getLogger();


    private Method getMethodForAnnoation(MethodCondition annotation, Class<?> testClass) {
        Method result = null;
        if (!annotation.clazz().equals(Exception.class)) {
            try {
                Arrays.asList(annotation.clazz().getDeclaredMethods()).forEach((Method i) -> {
                    i.setAccessible(true);
                });
                try {
                    result = annotation.clazz().getDeclaredMethod(annotation.method(), ExtensionContext.class);
                }
                catch (NoSuchMethodException e) {
                    result = annotation.clazz().getDeclaredMethod(annotation.method());
                }
            } catch (Exception ignored) {

            }
        }
        else {
            try {
                Arrays.asList(testClass.getDeclaredMethods()).forEach((Method i) -> {
                    i.setAccessible(true);
                });
                try {
                    result = testClass.getDeclaredMethod(annotation.method(), ExtensionContext.class);
                }
                catch (NoSuchMethodException e) {
                    result = testClass.getDeclaredMethod(annotation.method());
                }
            } catch (Exception ignored) {
                LOGGER.error("Method of MethodCondition annotation could not be found");
                return null;
            }
        }

        return result;
    }

    private ConditionEvaluationResult executeMethod(Method m, ExtensionContext context) {
        String identifier = m.getDeclaringClass().getName() + "." + m.getName();
        try {
            m.setAccessible(true);
            Optional<Object> testInstanceOpt = context.getTestInstance();
            Object testInstance;
            if (testInstanceOpt.isPresent() && m.getDeclaringClass().equals(testInstanceOpt.get().getClass())) {
                testInstance = testInstanceOpt.get();
            } else {
                Class<?> clzz = m.getDeclaringClass();
                Constructor<?> c = clzz.getDeclaredConstructor();
                c.setAccessible(true);
                testInstance = c.newInstance();
            }

            Object result;
            if (m.getParameterCount() > 0) {
                result = m.invoke(testInstance, context);
            }
            else {
                result = m.invoke(testInstance);
            }

            if (result.getClass().equals(ConditionEvaluationResult.class)) {
                return (ConditionEvaluationResult)result;
            }
            LOGGER.error(identifier + " should return a " + "ConditionEvaluationResult" + " object");
            return ConditionEvaluationResult.disabled("Invalid return type of " + m.getName());
        }
        catch (IllegalAccessException e) {
            LOGGER.error("Couldn't execute " + identifier + ", make sure, that class, constructor and method is public.");
            LOGGER.error(e);
        }
        catch (Exception e) {
            LOGGER.error(e);
        }
        return ConditionEvaluationResult.disabled("Could not invoke method " + identifier);
    }

    @Override
    public ConditionEvaluationResult evaluateExecutionCondition(ExtensionContext context) {
        Class<?> clzz = context.getRequiredTestClass();
        Optional<Method> testM = context.getTestMethod();
        Method clzzCondMethod = null;
        Method methCondMethod = null;
        String identifier = clzz.getName();

        if (!testM.isPresent()) {
            return ConditionEvaluationResult.enabled("");
        }

        if (clzz.isAnnotationPresent(MethodCondition.class)) {
            MethodCondition clzzAnnotation = clzz.getAnnotation(MethodCondition.class);
            clzzCondMethod = getMethodForAnnoation(clzzAnnotation, clzz);
            if (clzzCondMethod == null) {
                throw new RuntimeException("Method of class (" + identifier + ") MethodCondition annotation could not be found");
            }
        }

        if (testM.get().isAnnotationPresent(MethodCondition.class)) {
            identifier += "." + testM.get().getName();
            MethodCondition methAnotation = testM.get().getAnnotation(MethodCondition.class);
            methCondMethod = getMethodForAnnoation(methAnotation, clzz);
            if (methCondMethod == null) {
                throw new RuntimeException("Method of MethodCondition (" + identifier + ") annotation could not be found");
            }
        }

        if (methCondMethod != null) {
            ConditionEvaluationResult result = executeMethod(methCondMethod, context);
            if (!result.isDisabled() && clzzCondMethod != null) {
                result = executeMethod(clzzCondMethod, context);
            }
            return result;
        }
        else if (clzzCondMethod != null) {
            return executeMethod(clzzCondMethod, context);
        }
        else {
            return ConditionEvaluationResult.enabled("MethodCondition not present");
        }
    }
}
