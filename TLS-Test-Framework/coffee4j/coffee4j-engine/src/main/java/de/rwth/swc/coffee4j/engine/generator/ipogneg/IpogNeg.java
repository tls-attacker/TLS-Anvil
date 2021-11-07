package de.rwth.swc.coffee4j.engine.generator.ipogneg;

import de.rwth.swc.coffee4j.engine.characterization.FaultCharacterizationConfiguration;
import de.rwth.swc.coffee4j.engine.TestModel;
import de.rwth.swc.coffee4j.engine.TupleList;
import de.rwth.swc.coffee4j.engine.constraint.ConstraintChecker;
import de.rwth.swc.coffee4j.engine.constraint.ConstraintCheckerFactory;
import de.rwth.swc.coffee4j.engine.generator.TestInputGroup;
import de.rwth.swc.coffee4j.engine.generator.TestInputGroupGenerator;
import de.rwth.swc.coffee4j.engine.generator.ipog.IpogAlgorithm;
import de.rwth.swc.coffee4j.engine.generator.ipog.IpogConfiguration;
import de.rwth.swc.coffee4j.engine.generator.ipog.ParameterCombinationFactory;
import de.rwth.swc.coffee4j.engine.generator.ipog.ParameterOrder;
import de.rwth.swc.coffee4j.engine.report.Reporter;
import de.rwth.swc.coffee4j.engine.util.Preconditions;

import java.util.Collection;
import java.util.List;
import java.util.function.Supplier;
import java.util.stream.Collectors;

public class IpogNeg implements TestInputGroupGenerator {

    private final ConstraintCheckerFactory factory;

    public IpogNeg(ConstraintCheckerFactory factory) {
        this.factory = factory;
    }

    @Override
    public Collection<Supplier<TestInputGroup>> generate(TestModel model, Reporter reporter) {
        Preconditions.notNull(model);
        Preconditions.notNull(reporter);

        return model.getErrorTupleLists().stream()
                .map(errorTuples -> createGroupSupplier(errorTuples, model, factory, reporter))
                .collect(Collectors.toList());
    }
    
    private Supplier<TestInputGroup> createGroupSupplier(TupleList errorTuples,
                                                         TestModel model,
                                                         ConstraintCheckerFactory factory,
                                                         Reporter reporter) {
        return () -> {
            final ConstraintChecker checker = factory.createConstraintCheckerWithNegation(model, errorTuples);

            return createTestInputGroup(checker, errorTuples, model, reporter);
        };
    }

    private TestInputGroup createTestInputGroup(ConstraintChecker checker,
                                                TupleList errorTuples,
                                                TestModel testModel,
                                                Reporter reporter) {
        final ParameterCombinationFactory factory = new NegativeTWiseParameterCombinationFactory(errorTuples);
        final ParameterOrder order = new NegativityAwareParameterOrder(errorTuples);

        final List<int[]> testInputs = new IpogAlgorithm(
                IpogConfiguration.ipogConfiguration()
                        .testModel(testModel)
                        .checker(checker)
                        .factory(factory)
                        .order(order)
                        .reporter(reporter)
                        .build()).generate();

        final FaultCharacterizationConfiguration faultCharacterizationConfiguration
                = new FaultCharacterizationConfiguration(testModel, checker, reporter);

        return new TestInputGroup(errorTuples, testInputs, faultCharacterizationConfiguration);
    }
}
