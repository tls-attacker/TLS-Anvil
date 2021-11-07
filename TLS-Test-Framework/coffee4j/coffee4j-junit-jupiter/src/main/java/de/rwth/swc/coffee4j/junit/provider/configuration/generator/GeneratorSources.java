package de.rwth.swc.coffee4j.junit.provider.configuration.generator;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * The repeatable variant of {@link GeneratorSource}.
 * <p>
 * This is more or less a copy of {@link org.junit.jupiter.params.provider.ArgumentsSources} from the
 * junit-jupiter-params project.
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface GeneratorSources {
    
    GeneratorSource[] value();
}
