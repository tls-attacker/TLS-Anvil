package de.rwth.swc.coffee4j.junit;

import de.rwth.swc.coffee4j.engine.generator.ipog.Ipog;
import de.rwth.swc.coffee4j.engine.report.ArgumentConverter;
import de.rwth.swc.coffee4j.junit.provider.configuration.ConfigurationFromMethod;
import de.rwth.swc.coffee4j.junit.provider.configuration.ConfigurationProvider;
import de.rwth.swc.coffee4j.junit.provider.configuration.ConfigurationSource;
import de.rwth.swc.coffee4j.junit.provider.model.ModelFromMethod;
import de.rwth.swc.coffee4j.junit.provider.model.ModelProvider;
import de.rwth.swc.coffee4j.junit.provider.model.ModelSource;
import de.rwth.swc.coffee4j.model.Combination;
import de.rwth.swc.coffee4j.model.InputParameterModel;
import de.rwth.swc.coffee4j.model.Parameter;
import de.rwth.swc.coffee4j.model.report.CombinationArgumentConverter;
import de.rwth.swc.coffee4j.model.report.ParameterArgumentConverter;
import de.rwth.swc.coffee4j.model.report.TupleListArgumentConverter;
import de.rwth.swc.coffee4j.model.report.ValueArgumentConverter;
import org.junit.jupiter.api.TestTemplate;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * This annotation is used to mark a method which is a combinatorial test.
 * <p>
 * To work with JUnit jupiter, the annotated method may not be private or static.
 * <p>
 * A combinatorial test must specify a {@link ModelProvider} via a
 * {@link ModelSource} or any composed annotation like
 * {@link ModelFromMethod}. Optionally, configuration of the combinatorial
 * test is also possible via a {@link ConfigurationProvider} using
 * a {@link ConfigurationSource}. by default, a
 * {@link de.rwth.swc.coffee4j.junit.provider.configuration.DelegatingConfigurationProvider} will be used, but
 * alternatively it is also possible to use custom configurations such as the
 * {@link ConfigurationFromMethod}. All configurable aspects have
 * sensible default. If only a {@link InputParameterModel} is specified, the combinatorial
 * test will be executed with a {@link Ipog},
 * no fault characterization and execution reporter, and some default
 * {@link ArgumentConverter} such as
 * {@link ParameterArgumentConverter}
 * {@link ValueArgumentConverter}
 * {@link TupleListArgumentConverter} and
 * {@link CombinationArgumentConverter}.
 * <p>
 * Since an arbitrary number of parameters can be injected into the test method via definition of the
 * {@link InputParameterModel}, a special order of parameters has to be preserved
 * in the method. The following rules need to be followed:
 * <p>
 * -zero or more normal parameters are declared first
 * -followed by zero or more aggregators
 * -followed by other parameters which are resolved by {@link org.junit.jupiter.api.extension.ParameterResolver} not
 * specific to combinatorial testing, for example another {@link org.junit.jupiter.api.extension.Extension}.
 * <p>
 * It is escpecially important that all normal parameters are declared in the same order as those in the
 * {@link InputParameterModel}. Otherwise it will not work.
 * <p>
 * {@link CombinatorialTest} may also be used as ameta-annotation in order to create a custom composed annotation
 * which inherits the semantics of a {@link CombinatorialTest}.
 * <p>
 * This type of test can not be used with junit-jupiter 5.3 parallel testing yet due to problems in the
 * {@link TestInputIterator}. As such, it is marked with {@link ExecutionMode#SAME_THREAD} so that it is
 * forcibly executed sequentially even if users use parallel testing in junit.
 * <p>
 * This annotation is more or less a copy of the {@link org.junit.jupiter.params.ParameterizedTest} annotation
 * provided in the junit-jupiter-params project.
 */
@Target({ElementType.ANNOTATION_TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Execution(ExecutionMode.SAME_THREAD)
@TestTemplate
@ExtendWith(CombinatorialTestExtension.class)
public @interface CombinatorialTest {
    
    /**
     * Defines a custom display name for individual invocations of the {@link CombinatorialTest}. Should never
     * be blank or consist of white spaces. This text is what is show in various IDEs to make a test identifiable
     * to the user.
     * <p>
     * Multiple placeholders are supported:
     * -{index}: given the current invocation index of the test starting with 1
     * -{combination}: the complete {@link Combination} which is tested by the test
     * -{PARAMETER_NAME}: the value of the {@link Parameter} with the given name in the
     * currently tested {@link Combination}
     * <p>
     * All placeholders are resolved using the {@link CombinatorialTestNameFormatter}.
     *
     * @return the name pattern for all test inputs in this {@link CombinatorialTest}
     */
    String name() default "[{index}] {combination}";
    
}
