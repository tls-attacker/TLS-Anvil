package de.rwth.swc.coffee4j.engine.constraint;

import de.rwth.swc.coffee4j.engine.TestModel;
import de.rwth.swc.coffee4j.engine.TupleList;

public interface ConstraintCheckerFactory {

    ConstraintChecker createConstraintChecker(TestModel testModel);

    ConstraintChecker createConstraintCheckerWithNegation(TestModel testModel,
                                                          TupleList toBeNegated);
}
