package de.rwth.swc.coffee4j.junit.provider.configuration.generator;

import de.rwth.swc.coffee4j.engine.constraint.HardConstraintCheckerFactory;
import de.rwth.swc.coffee4j.engine.generator.TestInputGroupGenerator;
import de.rwth.swc.coffee4j.engine.generator.ipog.Ipog;
import de.rwth.swc.coffee4j.junit.provider.Loader;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.support.AnnotationConsumerInitializer;
import org.junit.platform.commons.util.ReflectionUtils;

import java.lang.reflect.Method;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import static org.junit.platform.commons.util.AnnotationUtils.findRepeatableAnnotations;

/**
 * Class for loading multiple {@link TestInputGroupGenerator}s via {@link GeneratorProvider}. These providers are
 * discovered using the {@link GeneratorSource} repeatable annotations. As such, multiple {@link TestInputGroupGenerator}
 * provided by each {@link GeneratorSource} are aggregated into one single list in this loader.
 * <p>
 * If no {@link GeneratorSource} is registered, the default of one {@link Ipog} is loaded.
 */
public class GeneratorLoader implements Loader<List<TestInputGroupGenerator>> {
    
    private static final TestInputGroupGenerator DEFAULT_GENERATOR
            = new Ipog(new HardConstraintCheckerFactory());
    
    @Override
    public List<TestInputGroupGenerator> load(ExtensionContext extensionContext) {
        final Method testMethod = extensionContext.getRequiredTestMethod();
        
        final List<TestInputGroupGenerator> generators
                = findRepeatableAnnotations(testMethod, GeneratorSource.class)
                .stream()
                .map(GeneratorSource::value)
                .map(ReflectionUtils::newInstance)
                .map(provider -> AnnotationConsumerInitializer.initialize(testMethod, provider))
                .map(provider -> provider.provide(extensionContext))
                .filter(Objects::nonNull)
                .flatMap(Collection::stream).filter(Objects::nonNull)
                .collect(Collectors.toList());
        
        return generators.isEmpty() ? Collections.singletonList(DEFAULT_GENERATOR) : generators;
    }
}
