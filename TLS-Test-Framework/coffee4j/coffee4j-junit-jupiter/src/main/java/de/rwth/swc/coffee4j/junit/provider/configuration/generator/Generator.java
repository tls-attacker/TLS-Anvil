package de.rwth.swc.coffee4j.junit.provider.configuration.generator;


import de.rwth.swc.coffee4j.engine.constraint.ConstraintCheckerFactory;
import de.rwth.swc.coffee4j.engine.generator.TestInputGroup;
import de.rwth.swc.coffee4j.engine.generator.TestInputGroupGenerator;
import de.rwth.swc.coffee4j.junit.CombinatorialTest;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * This is a {@link GeneratorSource} using the {@link ConstructorBasedGeneratorProvider} to create new instances of a
 * {@link TestInputGroupGenerator} via a no-args constructor. Since multiple generators are allowed,
 * just return multiple classes in the {@link #algorithms()} method to register more generators, or use any other
 * {@link GeneratorSource} since {@link GeneratorSource} is a repeatable annotation.
 */
@Target({ElementType.ANNOTATION_TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@GeneratorSource(ConstructorBasedGeneratorProvider.class)
public @interface Generator {
    
    /**
     * @return the classes used to generate {@link TestInputGroup}s for a
     * {@link CombinatorialTest}. Need to have a no-args constructor
     */
    Class<? extends TestInputGroupGenerator>[] algorithms();

    Class<? extends ConstraintCheckerFactory>[] factories(); // TODO REFACTOR THIS WORKAROUND
}
