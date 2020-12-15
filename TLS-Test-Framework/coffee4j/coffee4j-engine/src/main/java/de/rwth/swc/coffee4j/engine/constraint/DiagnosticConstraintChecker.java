package de.rwth.swc.coffee4j.engine.constraint;

import de.rwth.swc.coffee4j.engine.TestModel;
import de.rwth.swc.coffee4j.engine.TupleList;
import de.rwth.swc.coffee4j.engine.util.IntArrayWrapper;
import de.rwth.swc.coffee4j.engine.util.Preconditions;
import it.unimi.dsi.fastutil.objects.Object2IntMap;
import org.chocosolver.solver.Model;
import org.chocosolver.solver.variables.IntVar;

import java.util.Arrays;
import java.util.Collection;

class DiagnosticConstraintChecker extends ModelBasedConstraintChecker {

    DiagnosticConstraintChecker(TestModel testModel,
                                TupleList diagnosedTupleList,
                                Collection<Constraint> hardConstraints,
                                Collection<Constraint> softConstraints,
                                Object2IntMap<IntArrayWrapper> thresholds) {
        super(createModel(testModel, diagnosedTupleList, hardConstraints, softConstraints, thresholds));

        Preconditions.notNull(thresholds);
        Preconditions.check(!thresholds.isEmpty());
    }

    private static Model createModel(TestModel testModel,
                                     TupleList diagnosedTupleList,
                                     Collection<Constraint> hardConstraints,
                                     Collection<Constraint> softConstraints,
                                     Object2IntMap<IntArrayWrapper> thresholds) {
        final Model model = new Model();

        createVariables(testModel, model);
        final IntVar threshold = createThresholdVariable(model, thresholds);
        createHardConstraints(hardConstraints, model);
        createSoftConstraints(softConstraints, model, threshold);
        createThresholdConstraints(model, diagnosedTupleList, threshold, thresholds);

        return model;
    }

    private static void createVariables(TestModel testModel, Model model) {
        for (int i = 0; i < testModel.getNumberOfParameters(); i++) {
            int parameterSize = testModel.getParameterSizes()[i];
            String key = String.valueOf(i);

            model.intVar(key, 0, parameterSize - 1);
        }
    }

    private static IntVar createThresholdVariable(Model model, Object2IntMap<IntArrayWrapper> thresholds) {
        int maxThreshold = thresholds.values().stream().mapToInt(i -> i).max().orElse(0);

        return model.intVar("threshold", 0, maxThreshold);
    }

    private static void createHardConstraints(Collection<Constraint> hardConstraints,
                                              Model model) {
        for (Constraint constraint : hardConstraints) {
            constraint.apply(model).post();
        }
    }

    private static void createSoftConstraints(Collection<Constraint> softConstraints,
                                              Model model,
                                              IntVar threshold) {
        final IntVar[] reifiedVars = new IntVar[softConstraints.size()];
        int index = 0;

        for (Constraint constraint : softConstraints) {
            reifiedVars[index++] = constraint.apply(model).reify().intVar();
        }

        final int[] weights = new int[softConstraints.size()];
        Arrays.fill(weights, 1);
        final IntVar sum = model.intVar("sum", 0, softConstraints.size());
        model.scalar(reifiedVars, weights, "=", sum).post();

        model.arithm(sum, "+", threshold, ">=", softConstraints.size()).post();
    }

    private static void createThresholdConstraints(Model model,
                                                   TupleList diagnosedTupleList,
                                                   IntVar threshold,
                                                   Object2IntMap<IntArrayWrapper> thresholds) {
        final ConstraintConverter converter = new ConstraintConverter();

        final int[] parameters = diagnosedTupleList.getInvolvedParameters();

        for(IntArrayWrapper wrapper : thresholds.keySet()) {
            createThresholdConstraint(model, threshold, thresholds, converter, parameters, wrapper);
        }
    }

    private static void createThresholdConstraint(Model model,
                                                  IntVar threshold,
                                                  Object2IntMap<IntArrayWrapper> thresholds,
                                                  ConstraintConverter converter,
                                                  int[] parameters,
                                                  IntArrayWrapper wrapper) {
        final int[] values = wrapper.getArray();
        final int thresholdValue = thresholds.getInt(wrapper);

        final org.chocosolver.solver.constraints.Constraint condition = converter
                .createConstraints(parameters, values, model);
        final org.chocosolver.solver.constraints.Constraint effect = model
                .arithm(threshold, "=", thresholdValue);

        model.ifThen(condition, effect);
    }
}