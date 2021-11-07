package de.rwth.swc.coffee4j.junit.provider.configuration;

import de.rwth.swc.coffee4j.junit.CombinatorialTest;
import de.rwth.swc.coffee4j.model.manager.CombinatorialTestConsumerManagerConfiguration;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * {@code ConfigurationSource} is an annotation used to register
 * {@linkplain ConfigurationProvider configuration providers} for the annotated test method.
 * <p>
 * This may also be used as a meta-annotation in order to create a custom composed annotation that inherits the
 * semantics of {@code ConfigurationSource} (demonstrated by {@link ConfigurationFromMethod}).
 * <p>
 * This is more or less a copy of {@link org.junit.jupiter.params.provider.ArgumentsSource} from the
 * junit-jupiter-params project.
 */
@Target({ElementType.ANNOTATION_TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
public @interface ConfigurationSource {
    
    /**
     * The type of {@link ConfigurationProvider} used to provide an
     * {@link CombinatorialTestConsumerManagerConfiguration} for a
     * {@link CombinatorialTest}.
     *
     * @return the {@link ConfigurationProvider} class
     */
    Class<? extends ConfigurationProvider> value();
}
