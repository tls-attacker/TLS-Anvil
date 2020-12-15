package de.rwth.swc.coffee4j.model.manager;

import de.rwth.swc.coffee4j.engine.constraint.HardConstraintCheckerFactory;
import de.rwth.swc.coffee4j.engine.generator.ipog.Ipog;
import de.rwth.swc.coffee4j.model.Combination;
import de.rwth.swc.coffee4j.model.InputParameterModel;
import de.rwth.swc.coffee4j.model.Parameter;
import de.rwth.swc.coffee4j.model.report.PrintStreamExecutionReporter;
import org.junit.jupiter.api.Test;

import static de.rwth.swc.coffee4j.engine.characterization.ben.Ben.ben;
import static de.rwth.swc.coffee4j.model.constraints.ConstraintBuilder.constrain;
import static de.rwth.swc.coffee4j.engine.conflict.ConflictDetectionConfiguration.disable;
import static de.rwth.swc.coffee4j.model.manager.CombinatorialTestConsumerManagerConfiguration.consumerManagerConfiguration;
import static org.junit.jupiter.api.Assertions.assertFalse;

class DemoTest {
    
    @Test
    void exampleTest() {
        final CombinatorialTestExecutionManager executor = new CombinatorialTestExecutionManager(
                consumerManagerConfiguration()
                        .executionReporter(new PrintStreamExecutionReporter())
                        .generator(new Ipog(new HardConstraintCheckerFactory()))
                        .faultCharacterizationAlgorithmFactory(ben())
                        .setConflictDetectionConfiguration(disable())
                        .build(),
                this::testFunction,
                InputParameterModel
                        .inputParameterModel("exampleTest")
                        .strength(2)
                        .parameters(
                                Parameter.parameter("param1").values(0, 1, 2),
                                Parameter.parameter("param2").values("0", "1", "2"),
                                Parameter.parameter("param3").values(0, 1, 2),
                                Parameter.parameter("param4").values(0, 1, 2))
                        .errorConstraint(
                                constrain("param1", "param3")
                                        .by((Integer firstValue, Integer thirdValue)
                                                -> firstValue == 0 && thirdValue != 1))
                        .build());
        executor.execute();
    }
    
    private void testFunction(Combination testInput) {
        final int firstValue = (Integer) testInput.getValue("param1").get();
        final String secondValue = (String) testInput.getValue("param2").get();

        assertFalse(firstValue == 1 && secondValue.equals("1"));
    }
}
