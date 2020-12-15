package de.rwth.swc.coffee4j.junit.provider.model;

import de.rwth.swc.coffee4j.junit.CombinatorialTest;
import de.rwth.swc.coffee4j.model.InputParameterModel;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * This is a {@link ModelSource} which provides access to values returned from a {@linkplain #value() factory method}
 * of the class in which this annotation is declared or from static factory methods in external classes referenced
 * by the fully qualified name (classname#methodname).
 *
 * <p>Factory methods within the test class must be {@code static} unless the
 * {@link org.junit.jupiter.api.TestInstance.Lifecycle#PER_CLASS PER_CLASS}
 * test instance lifecycle mode is used; whereas, factory methods in external
 * classes must always be {@code static}. In any case, factory methods must not
 * declare any parameters.
 * <p>
 * This is a more of less direct copy of {@link org.junit.jupiter.params.provider.MethodSource} from the
 * junit-jupiter-params project.
 */
@Target({ElementType.ANNOTATION_TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@ModelSource(MethodBasedProvider.class)
public @interface ModelFromMethod {
    
    /**
     * The name of the method from which a {@link InputParameterModel} can be loaded.
     * Consequently, the method defined by the value must either return a
     * {@link InputParameterModel} directly, or a
     * {@link InputParameterModel.Builder} which can be build. The method should not
     * require any parameters.
     * <p>
     * There are three valid ways to specify the factory method which should be used:
     * -empty string: this is the default and looks for a factory method in the same class as the test method and
     * with the same name as the test method. As a {@link CombinatorialTest} has at least
     * one parameter, java will allow methods with the same name, but no parameters
     * -the name of a method: The method needs to be in the same class as the test method
     * -a fully qualified name in the format of classname#methodname from which the testModel is then loaded
     *
     * @return the name of the method in one of the three schemas explained above
     */
    String value() default "";
    
}
