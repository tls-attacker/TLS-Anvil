package de.rwth.swc.coffee4j.engine.generator;

import de.rwth.swc.coffee4j.engine.characterization.FaultCharacterizationConfiguration;
import de.rwth.swc.coffee4j.engine.report.Reporter;
import de.rwth.swc.coffee4j.engine.TestModel;

import java.util.Collection;
import java.util.function.Supplier;

/**
 * Interface for all algorithms which can generate combinatorial test inputs.
 * If an algorithm only generates one set of test inputs like, for example,
 * IPOG, the algorithm only has to return a singleton set.
 * The concept of TestInputGroup was introduced to differentiate in negative
 * testing as these test inputs should be viewed separated from other, positive
 * test inputs (in fault characterization).
 *
 * @see TestInputGroup
 */
@FunctionalInterface
public interface TestInputGroupGenerator {
    
    /**
     * Generates a arbitrary number of {@link TestInputGroup} instances.
     * Each group should be individual in its {@link FaultCharacterizationConfiguration}.
     * This means that test inputs with the same input parameter testModel and
     * constraints checker should also be in the same test group as this
     * makes the process of fault characterization easier.
     * If further parameters than the {@link TestModel} need
     * to be used, provide constructor with which they can be set.
     *
     * @param model    the complete testModel with which the test input groups
     *                 should be constructed. Must not be {@code null}
     * @param reporter to report information from inside the generation
     * @return a supplier of a test input group. It may be the case that the
     * group is only generated when calling {@link Supplier#get()}.
     * This can be used to make the generation in a multithreaded
     * environment without having the generator manage the
     * parallelism.
     * @throws NullPointerException if the testModel is {@code null}
     */
    Collection<Supplier<TestInputGroup>> generate(TestModel model, Reporter reporter);
    
}
