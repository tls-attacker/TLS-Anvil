package de.rwth.swc.coffee4j.engine.constraint;

import de.rwth.swc.coffee4j.engine.TestModel;
import de.rwth.swc.coffee4j.engine.TupleList;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

class ConstraintCheckerUtil {

    private ConstraintCheckerUtil() {
    }

    static Constraint findErrorConstraintToBeNegated(TestModel testModel, TupleList toBeNegated) {
        return testModel.getErrorConstraints().stream()
                .filter(constraint -> constraint.getTupleList().getId() == toBeNegated.getId())
                .findFirst()
                .orElseThrow();
    }

    static List<Constraint> filterErrorConstraintToBeNegated(TestModel testModel, TupleList toBeNegated) {
        return testModel.getErrorConstraints().stream()
                .filter(constraint -> constraint.getTupleList().getId() != toBeNegated.getId())
                .collect(Collectors.toList());
    }

    static List<Constraint> errorConstraintsWithNegation(TestModel testModel, TupleList tupleList) {
        final List<Constraint> constraintsWithNegation = new ArrayList<>(testModel.getErrorConstraints().size());

        for (Constraint constraint : testModel.getErrorConstraints()) {
            if (constraint.getTupleList().getId() == tupleList.getId()) {
                constraintsWithNegation.add(negateConstraint(constraint));
            } else {
                constraintsWithNegation.add(constraint);
            }
        }

        return constraintsWithNegation;
    }

    static Constraint negateConstraint(Constraint constraint) {
        return new NegatedConstraint(constraint);
    }

    static boolean checkValidIdentifier(TestModel testModel, int identifier) {
        return testModel.getExclusionConstraints().stream()
                .anyMatch(constraint -> constraint.getTupleList().getId() == identifier)
                || testModel.getErrorConstraints().stream()
                .anyMatch(constraint -> constraint.getTupleList().getId() == identifier);
    }
}
