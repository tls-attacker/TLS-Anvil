package de.rwth.swc.coffee4j.junit.provider.configuration;

import de.rwth.swc.coffee4j.junit.CombinatorialTest;
import de.rwth.swc.coffee4j.junit.provider.Loader;
import de.rwth.swc.coffee4j.model.manager.CombinatorialTestConsumerManagerConfiguration;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.support.AnnotationConsumerInitializer;
import org.junit.platform.commons.JUnitException;
import org.junit.platform.commons.util.ReflectionUtils;

import java.lang.reflect.Method;
import java.util.Optional;

import static org.junit.platform.commons.util.AnnotationUtils.findAnnotation;

/**
 * Class for loading the defined configuration for a {@link CombinatorialTest}.
 * by default, this class uses the {@link DelegatingConfigurationProvider} provider to construct a new
 * {@link CombinatorialTestConsumerManagerConfiguration}, but instead it is also possible to provide exactly
 * one {@link ConfigurationSource}. Since {@link ConfigurationSource} is a meta-annotation, any inheriting
 * annotation such as {@link ConfigurationFromMethod} can also be found by this loader.
 */
public class ConfigurationLoader implements Loader<CombinatorialTestConsumerManagerConfiguration> {
    
    @Override
    public CombinatorialTestConsumerManagerConfiguration load(ExtensionContext extensionContext) {
        final Method testMethod = extensionContext.getRequiredTestMethod();
        
        final Optional<ConfigurationProvider> configurationProvider =
                findAnnotation(testMethod, ConfigurationSource.class)
                        .map(ConfigurationSource::value)
                        .map(ReflectionUtils::newInstance)
                        .map(provider -> AnnotationConsumerInitializer.initialize(testMethod, provider));

        final CombinatorialTestConsumerManagerConfiguration configuration = configurationProvider
                .orElseGet(DelegatingConfigurationProvider::new)
                .provide(extensionContext);
        
        if (configuration == null) {
            throw new JUnitException("A configuration has to be provided for a combinatorial test");
        }
        
        return configuration;
    }
}
