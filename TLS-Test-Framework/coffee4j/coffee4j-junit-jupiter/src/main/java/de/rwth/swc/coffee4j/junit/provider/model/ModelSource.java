package de.rwth.swc.coffee4j.junit.provider.model;

import de.rwth.swc.coffee4j.junit.CombinatorialTest;
import de.rwth.swc.coffee4j.model.InputParameterModel;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * {@code ModelSource} is an annotation used to register {@linkplain ModelProvider testModel providers} for the
 * annotated test method.
 * <p>
 * This may also be used as a meta-annotation in order to create a custom composed annotation that inherits the
 * semantics of {@code ModelSource} (demonstrated by {@link ModelFromMethod}).
 */
@Target({ElementType.ANNOTATION_TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
public @interface ModelSource {
    
    /**
     * The type of {@link ModelProvider} used to provide an {@link InputParameterModel} for a
     * {@link CombinatorialTest}.
     *
     * @return the {@link ModelProvider} class
     */
    Class<? extends ModelProvider> value();
    
}
