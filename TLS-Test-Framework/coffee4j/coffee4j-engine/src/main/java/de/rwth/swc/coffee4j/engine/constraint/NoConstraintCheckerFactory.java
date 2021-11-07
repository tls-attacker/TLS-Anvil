package de.rwth.swc.coffee4j.engine.constraint;

import de.rwth.swc.coffee4j.engine.TestModel;
import de.rwth.swc.coffee4j.engine.TupleList;

public class NoConstraintCheckerFactory implements ConstraintCheckerFactory {

    @Override
    public ConstraintChecker createConstraintChecker(TestModel testModel) {
        return new NoConstraintChecker();
    }

    @Override
    public ConstraintChecker createConstraintCheckerWithNegation(TestModel testModel, TupleList toBeNegated) {
        return new NoConstraintChecker();
    }
}
