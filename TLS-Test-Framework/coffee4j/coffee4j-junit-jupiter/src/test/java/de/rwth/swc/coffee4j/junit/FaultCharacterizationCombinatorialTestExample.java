package de.rwth.swc.coffee4j.junit;

import de.rwth.swc.coffee4j.engine.characterization.ben.Ben;
import de.rwth.swc.coffee4j.junit.provider.configuration.characterization.EnableFaultCharacterization;
import de.rwth.swc.coffee4j.junit.provider.configuration.reporter.Reporter;
import de.rwth.swc.coffee4j.junit.provider.model.ModelFromMethod;
import de.rwth.swc.coffee4j.model.InputParameterModel;
import de.rwth.swc.coffee4j.model.report.PrintStreamExecutionReporter;

import static de.rwth.swc.coffee4j.model.InputParameterModel.inputParameterModel;
import static de.rwth.swc.coffee4j.model.Parameter.parameter;
import static de.rwth.swc.coffee4j.model.constraints.ConstraintBuilder.constrain;
import static org.junit.jupiter.api.Assertions.assertFalse;

/**
 * An example {@link CombinatorialTest} demonstrating complete fault characterization capability. It also shows that
 * constraints are respected by BEN, since one fault is not found as it is hidden behind a constraint.
 * When executing this test, three test inputs should fail, and "Combination{param1=2, param6=1.1, param5=3}" should
 * be discovered as the only failure-inducing combination.
 */
class FaultCharacterizationCombinatorialTestExample {
    
    @CombinatorialTest
    @EnableFaultCharacterization(Ben.class)
    @ModelFromMethod("model")
    @Reporter(PrintStreamExecutionReporter.class)
    void combinatorialTest(int param1, String param2, int param3, boolean param4, int param5, float param6) {
        System.out.println(param1 + "\t" + param2 + "\t" + param3 + "\t" + param4 + "\t" + param5 + "\t" + param6);
        assertFalse((param1 == 1 && "one  ".equals(param2) && param4) || (param1 == 2 && param5 == 3 && param6 == 1.1f));
    }
    
    private static InputParameterModel.Builder model() {
        return inputParameterModel("test testModel")
                .strength(3)
                .parameters(
                        parameter("param1").values(1, 2, 3),
                        parameter("param2").values("one  ", "two  ", "three"),
                        parameter("param3").values(1, 2, 3),
                        parameter("param4").values(true, false),
                        parameter("param5").values(1, 2, 3),
                        parameter("param6").values(1.1f, 2.2f, 3.3f)
                ).exclusionConstraint(
                        constrain("param1", "param2", "param4")
                                .by((Integer firstValue, String secondValue, Boolean fourthValue)
                                        -> !(firstValue == 1 && "one  ".equals(secondValue) && fourthValue))
                );
    }
    
}
