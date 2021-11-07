package de.rwth.swc.coffee4j.engine.constraint;

import de.rwth.swc.coffee4j.engine.util.Preconditions;
import org.chocosolver.solver.Model;
import org.chocosolver.solver.constraints.Constraint;
import org.chocosolver.solver.variables.IntVar;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static de.rwth.swc.coffee4j.engine.util.ChocoUtil.findVariable;

class ModelBasedConstraintChecker implements ConstraintChecker {

    private final Model model;

    ModelBasedConstraintChecker(Model model) {
        this.model = Preconditions.notNull(model);
    }

    @Override
    public boolean isValid(final int[] combination) {
        final List<Constraint> constraintsList = createAssignmentConstraints(combination, model);
        
        return runChocoSolver(model, constraintsList);
    }
    
    private List<Constraint> createAssignmentConstraints(final int[] combination, final Model model) {
        final List<Constraint> constraints = new ArrayList<>();
        
        for (int i = 0; i < combination.length; i++) {
            if (combination[i] != -1) {
                addAssignmentConstraint(i, combination[i], model, constraints);
            }
        }
        
        return constraints;
    }

    private void addAssignmentConstraint(int parameter, int value, Model model, List<Constraint> constraints) {
        if (value == -1) {
            return;
        }

        final Optional<IntVar> candidate = findVariable(model, parameter)
                .filter(v -> v instanceof IntVar)
                .map(v -> (IntVar) v);

        final IntVar variable = candidate.orElseThrow();

        final Constraint constraint = model.arithm(variable, "=", value);
        constraints.add(constraint);
    }
    
    @Override
    public boolean isExtensionValid(int[] combination, int... parameterValues) {
        Preconditions.check(parameterValues.length % 2 == 0);
        
        final List<Constraint> constraintsList = createAssignmentConstraints(combination, model);
        
        for (int i = 0; i < parameterValues.length; i += 2) {
            addAssignmentConstraint(parameterValues[i], parameterValues[i + 1], model, constraintsList);
        }
        
        return runChocoSolver(model, constraintsList);
    }
    
    @Override
    public boolean isDualValid(int[] parameters, int[] values) {
        Preconditions.check(parameters.length == values.length);
        
        final List<Constraint> constraintsList = new ArrayList<>(parameters.length);
        for (int i = 0; i < parameters.length; i++) {
            addAssignmentConstraint(parameters[i], values[i], model, constraintsList);
        }
        
        return runChocoSolver(model, constraintsList);
    }

    private boolean runChocoSolver(Model model, List<Constraint> temporaryConstraints) {
        final Constraint[] constraints = temporaryConstraints.toArray(new Constraint[0]);

        model.post(constraints);

        final boolean result = model.getSolver().solve();

        model.unpost(constraints);
        model.getSolver().reset();

        return result;
    }
}
