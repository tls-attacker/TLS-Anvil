package de.rub.nds.tlstest.framework.coffee4j.junit;

import de.rwth.swc.coffee4j.model.Combination;
import de.rwth.swc.coffee4j.model.Parameter;
import org.junit.jupiter.api.TestTemplate;
import org.junit.jupiter.api.extension.ExtendWith;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

@Target({ElementType.ANNOTATION_TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@TestTemplate
@ExtendWith(CombinatorialTestExtension.class)
@Execution(ExecutionMode.SAME_THREAD)
@Deprecated
public @interface CombinatorialTlsTest {
    
    /**
     * Defines a custom display name for individual invocations of the {@link CombinatorialTlsTest}. Should never
     * be blank or consist of white spaces. This text is what is show in various IDEs to make a test identifiable
     * to the user.
     * <p>
     * Multiple placeholders are supported:
     * -{index}: given the current invocation index of the test starting with 1
     * -{combination}: the complete {@link Combination} which is tested by the test
     * -{PARAMETER_NAME}: the value of the {@link Parameter} with the given name in the
     * currently tested {@link Combination}
     * <p>
     * All placeholders are resolved using the {@link de.rwth.swc.coffee4j.junit.CombinatorialTestNameFormatter}.
     *
     * @return the name pattern for all test inputs in this {@link CombinatorialTlsTest}
     */
    String name() default "[{index}] {combination}";
    
}
