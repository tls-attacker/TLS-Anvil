package de.rub.nds.tlstest.suite;

import static org.junit.Assert.assertTrue;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import de.rub.nds.anvilcore.annotation.*;
import de.rub.nds.anvilcore.junit.extension.MethodConditionExtension;
import de.rub.nds.anvilcore.model.parameter.ParameterIdentifier;
import de.rub.nds.tlstest.framework.anvil.TlsParameterIdentifierProvider;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.Test;
import org.reflections.Reflections;
import org.reflections.scanners.MethodAnnotationsScanner;

public class AnnotationReferences {
    @Test
    public void referencesMatchParameterIdentifiers() {
        List<String> knownIdentifierStrings =
                new TlsParameterIdentifierProvider()
                        .generateAllParameterIdentifiers().stream()
                                .map(ParameterIdentifier::name)
                                .collect(Collectors.toList());
        Reflections reflections =
                new Reflections("de.rub.nds.tlstest", new MethodAnnotationsScanner());
        Set<Method> testMethods =
                reflections.getMethodsAnnotatedWith(NonCombinatorialAnvilTest.class);
        testMethods.addAll(reflections.getMethodsAnnotatedWith(AnvilTest.class));
        for (Method method : testMethods) {
            Set<String> identifiers = collectAnnotationIdentifiers(method);
            identifiers.forEach(
                    identifier ->
                            assertTrue(
                                    "Found unknown ParameterIdentifier '"
                                            + identifier
                                            + "' for test "
                                            + method.getName(),
                                    knownIdentifierStrings.contains(identifier)));
        }
    }

    private Set<String> collectAnnotationIdentifiers(Method method) {
        Set<String> annotationIdentifiers = new HashSet<>();
        if (method.isAnnotationPresent(ExplicitModelingConstraints.class)) {
            annotationIdentifiers.addAll(
                    Arrays.asList(
                            method.getAnnotation(ExplicitModelingConstraints.class)
                                    .affectedIdentifiers()));
        }
        if (method.isAnnotationPresent(DynamicValueConstraints.class)) {
            annotationIdentifiers.addAll(
                    Arrays.asList(
                            method.getAnnotation(DynamicValueConstraints.class)
                                    .affectedIdentifiers()));
        }
        if (method.isAnnotationPresent(ExplicitValues.class)) {
            annotationIdentifiers.addAll(
                    Arrays.asList(
                            method.getAnnotation(ExplicitValues.class).affectedIdentifiers()));
        }
        if (method.isAnnotationPresent(ManualConfig.class)) {
            annotationIdentifiers.addAll(
                    Arrays.asList(method.getAnnotation(ManualConfig.class).identifiers()));
        }
        return annotationIdentifiers;
    }

    @Test
    public void referencesMatchMethodConditions() {
        Reflections reflections =
                new Reflections("de.rub.nds.tlstest", new MethodAnnotationsScanner());
        Set<Method> testMethods = reflections.getMethodsAnnotatedWith(MethodCondition.class);
        for (Method method : testMethods) {
            Class<?> methodClass = method.getDeclaringClass();
            MethodCondition methodCondition = method.getAnnotation(MethodCondition.class);
            assertNotNull(
                    MethodConditionExtension.getMethodForAnnotation(methodCondition, methodClass));
        }
    }
}
