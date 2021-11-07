package de.rwth.swc.coffee4j.engine.constraint;

import de.rwth.swc.coffee4j.engine.TestModel;
import de.rwth.swc.coffee4j.engine.TupleList;
import de.rwth.swc.coffee4j.engine.util.Preconditions;

import static de.rwth.swc.coffee4j.engine.constraint.ConstraintCheckerUtil.checkValidIdentifier;
import static de.rwth.swc.coffee4j.engine.constraint.ConstraintCheckerUtil.errorConstraintsWithNegation;

public class HardConstraintCheckerFactory implements ConstraintCheckerFactory {

    @Override
    public ConstraintChecker createConstraintChecker(TestModel testModel) {
        return new HardConstraintChecker(
                testModel,
                testModel.getExclusionConstraints(),
                testModel.getErrorConstraints());
    }

    @Override
    public ConstraintChecker createConstraintCheckerWithNegation(TestModel testModel, TupleList toBeNegated) {
        Preconditions.check(checkValidIdentifier(testModel, toBeNegated.getId()));

        return new HardConstraintChecker(
                testModel,
                testModel.getExclusionConstraints(),
                errorConstraintsWithNegation(testModel, toBeNegated));
    }
}
