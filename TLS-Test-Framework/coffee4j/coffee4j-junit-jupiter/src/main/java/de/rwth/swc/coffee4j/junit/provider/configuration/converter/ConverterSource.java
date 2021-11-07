package de.rwth.swc.coffee4j.junit.provider.configuration.converter;

import de.rwth.swc.coffee4j.engine.report.ArgumentConverter;

import java.lang.annotation.ElementType;
import java.lang.annotation.Repeatable;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * {@code ConverterSource} is an annotation used to register
 * {@linkplain ConverterProvider converter providers} for the annotated test method.
 * <p>
 * This may also be used as a meta-annotation in order to create a custom composed annotation that inherits the
 * semantics of {@code ConverterSource} (demonstrated by {@link Converter}).
 * <p>
 * This annotation is repeatable via {@link ConverterSources}, and as such multiple providers can be registered.
 * <p>
 * This is more or less a copy of {@link org.junit.jupiter.params.provider.ArgumentsSource} from the
 * junit-jupiter-params project.
 */
@Target({ElementType.ANNOTATION_TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Repeatable(ConverterSources.class)
public @interface ConverterSource {
    
    /**
     * @return the class which provides {@link ArgumentConverter}s. Must have a
     * no-args constructor
     */
    Class<? extends ConverterProvider> value();
    
}
