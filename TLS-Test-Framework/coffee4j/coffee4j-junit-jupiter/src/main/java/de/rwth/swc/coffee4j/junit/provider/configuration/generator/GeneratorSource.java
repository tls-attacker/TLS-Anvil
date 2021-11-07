package de.rwth.swc.coffee4j.junit.provider.configuration.generator;

import de.rwth.swc.coffee4j.engine.generator.TestInputGroupGenerator;

import java.lang.annotation.ElementType;
import java.lang.annotation.Repeatable;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * {@code GeneratorSource} is an annotation used to register
 * {@linkplain GeneratorProvider generator providers} for the annotated test method.
 * <p>
 * This may also be used as a meta-annotation in order to create a custom composed annotation that inherits the
 * semantics of {@code GeneratorSource} (demonstrated by {@link Generator}).
 * <p>
 * This annotation is repeatable via {@link GeneratorSources}, and as such multiple providers can be registered.
 * <p>
 * This is more or less a copy of {@link org.junit.jupiter.params.provider.ArgumentsSource} from the
 * junit-jupiter-params project.
 */
@Target({ElementType.ANNOTATION_TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Repeatable(GeneratorSources.class)
public @interface GeneratorSource {
    
    /**
     * @return the class which provides {@link TestInputGroupGenerator}s. Must
     * have a no-args constructor
     */
    Class<? extends GeneratorProvider> value();
}
