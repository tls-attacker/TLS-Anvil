package de.rwth.swc.coffee4j.engine.generator.ipog;

import de.rwth.swc.coffee4j.engine.TestModel;
import de.rwth.swc.coffee4j.engine.characterization.FaultCharacterizationConfiguration;
import de.rwth.swc.coffee4j.engine.constraint.ConstraintCheckerFactory;
import de.rwth.swc.coffee4j.engine.report.Reporter;
import de.rwth.swc.coffee4j.engine.generator.TestInputGroup;
import de.rwth.swc.coffee4j.engine.generator.TestInputGroupGenerator;

import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.function.Supplier;

/**
 * Generator for one test group containing the test inputs generated with the
 * {@link IpogAlgorithm} algorithm using no constraints and the normal parameter order
 * with the strength given by the {@link TestModel}.
 */
public class Ipog implements TestInputGroupGenerator {
    
    private static final String DISPLAY_NAME = "Positive IpogAlgorithm Tests";

    private final ConstraintCheckerFactory factory;

    public Ipog(ConstraintCheckerFactory factory) {
        this.factory = factory;
    }

    /**
     * Constructs a combinatorial test suite for positive testing.
     * This means that each combination of the given strength is guaranteed
     * to be covered by at least one test input returned by this method.
     *
     * @param model    the complete testModel with which the test input groups
     *                 should be constructed. Must not be {@code null}
     * @param reporter to report information from inside the generation
     * @return a test suite meeting the criteria described above
     */
    @Override
    public Set<Supplier<TestInputGroup>> generate(TestModel model, Reporter reporter) {
        if(model.getStrength() == 0) {
            return Collections.emptySet();
        }

        return Collections.singleton(() -> {
            final List<int[]> testInputs = new IpogAlgorithm(
                    IpogConfiguration.ipogConfiguration()
                            .testModel(model)
                            .checker(factory.createConstraintChecker(model))
                            .build()).generate();
            final FaultCharacterizationConfiguration faultCharacterizationConfiguration
                    = new FaultCharacterizationConfiguration(model, factory.createConstraintChecker(model), reporter);

            return new TestInputGroup(DISPLAY_NAME, testInputs, faultCharacterizationConfiguration);
        });
    }
}
