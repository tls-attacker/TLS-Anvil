package de.rwth.swc.coffee4j.junit.provider.configuration.diagnosis;

import de.rwth.swc.coffee4j.junit.provider.Loader;
import de.rwth.swc.coffee4j.engine.conflict.ConflictDetectionConfiguration;
import org.junit.jupiter.api.extension.ExtensionContext;

import java.lang.reflect.Method;
import java.util.Optional;

import static org.junit.platform.commons.util.AnnotationUtils.findAnnotation;

public class ConflictDetectionConfigurationLoader implements Loader<ConflictDetectionConfiguration> {

    @Override
    public ConflictDetectionConfiguration load(ExtensionContext extensionContext) {
        final Method testMethod = extensionContext.getRequiredTestMethod();

        final Optional<EnableConflictDetection> optional =
                findAnnotation(testMethod, EnableConflictDetection.class);

        return optional
                .map(annotation ->
                        new ConflictDetectionConfiguration(
                                true, annotation.shouldAbort(),
                                annotation.explainConflicts(), annotation.conflictExplanationAlgorithm(),
                                annotation.diagnoseConflicts(), annotation.conflictDiagnosisAlgorithm()))
                .orElseGet(ConflictDetectionConfiguration::disable);
    }
}