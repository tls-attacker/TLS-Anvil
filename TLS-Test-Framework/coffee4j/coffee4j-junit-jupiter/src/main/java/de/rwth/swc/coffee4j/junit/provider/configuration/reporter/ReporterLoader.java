package de.rwth.swc.coffee4j.junit.provider.configuration.reporter;

import de.rwth.swc.coffee4j.junit.provider.Loader;
import de.rwth.swc.coffee4j.model.report.ExecutionReporter;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.support.AnnotationConsumerInitializer;
import org.junit.platform.commons.util.ReflectionUtils;

import java.lang.reflect.Method;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import static org.junit.platform.commons.util.AnnotationUtils.findRepeatableAnnotations;

/**
 * Class for loading multiple {@link ExecutionReporter}s via {@link ReporterProvider}. These providers are
 * discovered using the {@link ReporterSource} repeatable annotations. As such, multiple {@link ExecutionReporter}
 * provided by each {@link ReporterSource} are aggregated into one single list in this loader.
 */
public class ReporterLoader implements Loader<List<ExecutionReporter>> {
    
    @Override
    public List<ExecutionReporter> load(ExtensionContext extensionContext) {
        final Method testMethod = extensionContext.getRequiredTestMethod();
        
        return findRepeatableAnnotations(testMethod, ReporterSource.class)
                .stream()
                .map(ReporterSource::value)
                .map(ReflectionUtils::newInstance)
                .map(provider -> AnnotationConsumerInitializer.initialize(testMethod, provider))
                .map(provider -> provider.provide(extensionContext))
                .filter(Objects::nonNull)
                .flatMap(Collection::stream)
                .filter(Objects::nonNull)
                .collect(Collectors.toList());
    }
}
