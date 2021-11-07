package de.rwth.swc.coffee4j.junit.provider.configuration;

import de.rwth.swc.coffee4j.model.manager.CombinatorialTestConsumerManagerConfiguration;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.support.AnnotationConsumer;
import org.junit.platform.commons.JUnitException;

import static de.rwth.swc.coffee4j.junit.provider.ProviderUtil.getObjectReturnedByMethod;

/**
 * A provider loading a class from a method as described in {@link ConfigurationFromMethod}.
 * <p>
 * This is a more or less direct copy of org.junit.jupiter.params.provider.MethodArgumentsProvider from the
 * junit-jupiter-params project.
 */
class MethodBasedProvider implements ConfigurationProvider, AnnotationConsumer<ConfigurationFromMethod> {
    
    private String methodName;
    
    @Override
    public void accept(ConfigurationFromMethod configurationFromMethod) {
        methodName = configurationFromMethod.value();
    }
    
    @Override
    public CombinatorialTestConsumerManagerConfiguration provide(ExtensionContext extensionContext) {
        final Object providedObject = getObjectReturnedByMethod(extensionContext, methodName);
        return toConfiguration(providedObject);
    }
    
    private static CombinatorialTestConsumerManagerConfiguration toConfiguration(Object object) {
        if (object instanceof CombinatorialTestConsumerManagerConfiguration) {
            return (CombinatorialTestConsumerManagerConfiguration) object;
        } else if (object instanceof CombinatorialTestConsumerManagerConfiguration.Builder) {
            return ((CombinatorialTestConsumerManagerConfiguration.Builder) object).build();
        } else {
            throw new JUnitException("The given method must either return a " + CombinatorialTestConsumerManagerConfiguration.class.getName() + " or a " + CombinatorialTestConsumerManagerConfiguration.Builder.class.getName() + ". Instead a " + object.getClass().getName() + " was returned");
        }
    }
}
