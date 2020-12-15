package de.rwth.swc.coffee4j.engine.constraint;

import de.rwth.swc.coffee4j.engine.TestModel;
import de.rwth.swc.coffee4j.engine.util.Preconditions;
import org.chocosolver.solver.Model;
import org.chocosolver.solver.variables.IntVar;

import java.util.Arrays;
import java.util.Collection;

class SoftConstraintChecker extends ModelBasedConstraintChecker {

    SoftConstraintChecker(TestModel testModel,
                          Collection<Constraint> hardConstraints,
                          Collection<Constraint> softConstraints,
                          int threshold) {
        super(createModel(testModel, hardConstraints, softConstraints, threshold));

        Preconditions.check(0 <= threshold && threshold <= softConstraints.size());
    }

    private static Model createModel(TestModel testModel,
                                     Collection<Constraint> hardConstraints,
                                     Collection<Constraint> softConstraints,
                                     int threshold) {
        final Model model = new Model();
        createVariables(testModel, model);
        createHardConstraints(hardConstraints, model);
        createSoftConstraints(softConstraints, threshold, model);

        return model;
    }

    private static void createVariables(TestModel testModel, Model model) {
        for (int i = 0; i < testModel.getNumberOfParameters(); i++) {
            int parameterSize = testModel.getParameterSizes()[i];
            String key = String.valueOf(i);

            model.intVar(key, 0, parameterSize - 1);
        }
    }

    private static void createHardConstraints(Collection<Constraint> hardConstraints,
                                              Model model) {
        for (Constraint constraint : hardConstraints) {
            constraint.apply(model).post();
        }
    }

    private static void createSoftConstraints(Collection<Constraint> softConstraints,
                                              int threshold,
                                              Model model) {
        final IntVar[] reifiedVars = new IntVar[softConstraints.size()];
        int index = 0;

        for (Constraint constraint : softConstraints) {
            reifiedVars[index++] = constraint.apply(model).reify().intVar();
        }

        final int[] weights = new int[softConstraints.size()];
        Arrays.fill(weights, 1);
        final IntVar sum = model.intVar("sum", 0, softConstraints.size());

        model.arithm(sum, ">=", (softConstraints.size() - threshold)).post();
        model.scalar(reifiedVars, weights, "=", sum).post();
    }
}