package de.rwth.swc.coffee4j.engine.conflict.choco;

import de.rwth.swc.coffee4j.engine.constraint.Constraint;
import de.rwth.swc.coffee4j.engine.util.Preconditions;
import it.unimi.dsi.fastutil.ints.IntOpenHashSet;
import it.unimi.dsi.fastutil.ints.IntSet;
import org.chocosolver.solver.Model;
import org.chocosolver.solver.variables.IntVar;
import org.chocosolver.solver.variables.Variable;

import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

public class ChocoModel {

    private final Model model;
    private final List<ChocoConstraint> enabledConstraints;
    private final List<ChocoConstraint> disabledConstraints;

    private ChocoConstraint assignmentConstraint;
    private ChocoConstraint originalNegatedConstraint;
    private ChocoConstraint oppositeNegatedConstraint;

    public ChocoModel(int[] parameterSizes, List<Constraint> constraints) {
        Preconditions.notNull(parameterSizes);
        Preconditions.notNull(constraints);
        checkDuplicateIds(constraints);

        this.model = new Model();
        this.enabledConstraints = new ArrayList<>();
        this.disabledConstraints = new ArrayList<>();
        this.assignmentConstraint = null;
        this.originalNegatedConstraint = null;
        this.oppositeNegatedConstraint = null;

        createVariables(parameterSizes);

        for(Constraint constraint : constraints) {
            final ChocoConstraint chocoConstraint = createAndPostConstraint(constraint);

            this.enabledConstraints.add(chocoConstraint);
        }
    }

    private void checkDuplicateIds(List<Constraint> constraints) {
        IntSet uniques = new IntOpenHashSet(constraints.size());

        for (Constraint constraint : constraints) {
            Preconditions.check(
                    uniques.add(constraint.getTupleList().getId()),
                    "duplicate id " + constraint.getTupleList().getId()
            );
        }
    }

    public boolean isSatisfiable() {
        return model.getSolver().solve();
    }

    public void reset() {
        model.getSolver().reset();
    }

    public int setAssignmentConstraint(int[] parameters, int[] values) {
        Preconditions.notNull(parameters);
        Preconditions.notNull(values);
        Preconditions.check(parameters.length == values.length);

        clearAssignmentConstraint();

        final org.chocosolver.solver.constraints.Constraint[] tmp = model.getCstrs();
        final org.chocosolver.solver.constraints.Constraint[] arithms
                = new org.chocosolver.solver.constraints.Constraint[parameters.length];

        for(int i = 0; i < parameters.length; i++) {
            final int parameter = parameters[i];
            final int value = values[i];

            final Optional<Variable> candidate = findVariable(parameter);
            final IntVar variable = (IntVar) candidate.orElseThrow();

            arithms[i] = model.arithm(variable, "=", value);
        }

        final org.chocosolver.solver.constraints.Constraint constraint = model.and(arithms);
        model.post(constraint);

        final org.chocosolver.solver.constraints.Constraint[] allConstraints
                = exclude(model.getCstrs(), tmp);
        assignmentConstraint = new ChocoConstraint(
                findNextUnusedId(),
                constraint,
                allConstraints,
                ChocoConstraintStatus.POSTED);

        enabledConstraints.add(assignmentConstraint);

        return assignmentConstraint.getId();
    }

    public boolean isAssignmentConstraintSet() {
        return assignmentConstraint != null;
    }

    public void clearAssignmentConstraint() {
        if(assignmentConstraint != null) {
            model.unpost(assignmentConstraint.getAllConstraints());

            if(!enabledConstraints.removeIf(constraint -> constraint.getId() == assignmentConstraint.getId())) {
                disabledConstraints.removeIf(constraint -> constraint.getId() == assignmentConstraint.getId());
            }

            assignmentConstraint = null;
        }
    }

    public void setNegationOfConstraint(int id) {
        resetNegationOfConstraint();

        originalNegatedConstraint = findConstraintById(enabledConstraints, id)
                .orElseThrow(() -> new IllegalArgumentException(
                        MessageFormat.format("no enabled constraint with id {0} found", id))
                );
        model.unpost(originalNegatedConstraint.getAllConstraints());
        enabledConstraints.remove(originalNegatedConstraint);

        final org.chocosolver.solver.constraints.Constraint[] tmp = model.getCstrs();

        final org.chocosolver.solver.constraints.Constraint rootConstraint
                = originalNegatedConstraint.getRootConstraint().getOpposite();
        model.post(rootConstraint);

        final org.chocosolver.solver.constraints.Constraint[] allConstraints = exclude(model.getCstrs(), tmp);
        oppositeNegatedConstraint = new ChocoConstraint(originalNegatedConstraint.getId(), rootConstraint, allConstraints, ChocoConstraintStatus.POSTED);

        enabledConstraints.add(oppositeNegatedConstraint);
    }

    public boolean hasNegatedConstraint() {
        return originalNegatedConstraint != null;
    }

    public void resetNegationOfConstraint() {
        if(originalNegatedConstraint != null) {
            model.unpost(oppositeNegatedConstraint.getAllConstraints());
            model.post(originalNegatedConstraint.getAllConstraints());

            if(!enabledConstraints.removeIf(constraint -> constraint.getId() == oppositeNegatedConstraint.getId())) {
                disabledConstraints.removeIf(constraint -> constraint.getId() == oppositeNegatedConstraint.getId());
            }

            enabledConstraints.add(originalNegatedConstraint);

            originalNegatedConstraint = null;
            oppositeNegatedConstraint = null;
        }
    }

    public void enableConstraint(int id) {
        final ChocoConstraint constraint = findConstraintById(disabledConstraints, id)
                .orElseThrow(() -> new IllegalArgumentException(
                        MessageFormat.format("no disabled constraint with id {0} found", id)));

        model.post(constraint.getAllConstraints());
        constraint.setStatus(ChocoConstraintStatus.POSTED);

        disabledConstraints.remove(constraint);
        enabledConstraints.add(constraint);
    }

    public void disableConstraint(int id) {
        final ChocoConstraint constraint = findConstraintById(enabledConstraints, id)
                .orElseThrow(() -> new IllegalArgumentException(
                        MessageFormat.format("no enabled constraint with id {0} found", id)));

        model.unpost(constraint.getAllConstraints());
        constraint.setStatus(ChocoConstraintStatus.UNPOSTED);

        enabledConstraints.remove(constraint);
        disabledConstraints.add(constraint);
    }

    public void enableConstraints(int ... ids) {
        for(int id : ids) {
            enableConstraint(id);
        }
    }

    public void disableConstraints(int ... ids) {
        for(int id : ids) {
            disableConstraint(id);
        }
    }

    public void enableAllConstraints() {
        for(ChocoConstraint constraint : disabledConstraints) {
            model.post(constraint.getAllConstraints());
            constraint.setStatus(ChocoConstraintStatus.POSTED);
        }

        enabledConstraints.addAll(disabledConstraints);
        disabledConstraints.clear();
    }

    public void disableAllConstraints() {
        for(ChocoConstraint constraint : enabledConstraints) {
            if(constraint.getStatus().equals(ChocoConstraintStatus.POSTED)) {
                model.unpost(constraint.getAllConstraints());
                constraint.setStatus(ChocoConstraintStatus.UNPOSTED);
            }
        }

        disabledConstraints.addAll(enabledConstraints);
        enabledConstraints.clear();
    }

    public boolean allConstraintsEnabled() {
        return disabledConstraints.isEmpty();
    }

    private int findNextUnusedId() {
        int id = enabledConstraints.size() + disabledConstraints.size();

        while(!isIdUnused(id)) {
            id++;
        }

        return id;
    }

    private boolean isIdUnused(int id) {
        return enabledConstraints.stream().noneMatch(constraint -> constraint.getId() == id)
                && disabledConstraints.stream().noneMatch(constraint -> constraint.getId() == id);
    }

    private Optional<ChocoConstraint> findConstraintById(List<ChocoConstraint> constraints, int id) {
        return constraints.stream()
                .filter(constraint -> constraint.getId() == id)
                .findFirst();
    }

    private void createVariables(int[] parameterSizes) {
        for (int i = 0; i < parameterSizes.length; i++) {
            int parameterSize = parameterSizes[i];
            String key = String.valueOf(i);

            model.intVar(key, 0, parameterSize - 1);
        }
    }

    private ChocoConstraint createAndPostConstraint(Constraint constraint) {
        final org.chocosolver.solver.constraints.Constraint[] tmp = model.getCstrs();
        final org.chocosolver.solver.constraints.Constraint appliedConstraint = constraint.apply(model);

        model.post(appliedConstraint);

        final org.chocosolver.solver.constraints.Constraint[] allConstraints = exclude(model.getCstrs(), tmp);

        return new ChocoConstraint(
                constraint.getTupleList().getId(),
                appliedConstraint,
                allConstraints,
                ChocoConstraintStatus.POSTED);
    }

    private org.chocosolver.solver.constraints.Constraint[] exclude(
            org.chocosolver.solver.constraints.Constraint[] allConstraints,
            org.chocosolver.solver.constraints.Constraint[] excludedConstraints) {
        List<org.chocosolver.solver.constraints.Constraint> constraints = new ArrayList<>();

        for (org.chocosolver.solver.constraints.Constraint constraint : allConstraints) {
            if (!contains(constraint, excludedConstraints)) {
                constraints.add(constraint);
            }
        }

        return constraints.toArray(new org.chocosolver.solver.constraints.Constraint[0]);
    }

    private boolean contains(org.chocosolver.solver.constraints.Constraint constraint,
                             org.chocosolver.solver.constraints.Constraint[] excludedConstraints) {
        if(excludedConstraints.length == 0) {
            return false;
        }

        for (org.chocosolver.solver.constraints.Constraint excludedConstraint : excludedConstraints) {
            if (excludedConstraint.equals(constraint)) {
                return true;
            }
        }

        return false;
    }

    private Optional<Variable> findVariable(int parameter) {
        final String key = String.valueOf(parameter);

        return Arrays.stream(model.getVars())
                .filter(variable -> variable.getName().equals(key))
                .findFirst();
    }
}
