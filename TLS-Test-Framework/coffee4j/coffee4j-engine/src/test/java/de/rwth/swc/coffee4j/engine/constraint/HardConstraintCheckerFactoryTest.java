package de.rwth.swc.coffee4j.engine.constraint;

import de.rwth.swc.coffee4j.engine.TestModel;
import de.rwth.swc.coffee4j.engine.TupleList;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class HardConstraintCheckerFactoryTest {

    @Test
    void testCreateConstraintChecker() {
        final List<TupleList> forbiddenTupleLists = new ArrayList<>();
        forbiddenTupleLists.add(new TupleList(1, new int[]{0, 1}, Arrays.asList(new int[]{0, 0}, new int[]{1, 1})));

        final TestModel model = new TestModel(2, new int[]{2, 2, 2}, forbiddenTupleLists, Collections.emptyList());

        final ConstraintChecker solver = new HardConstraintCheckerFactory().createConstraintChecker(model);
        final ConstraintChecker otherSolver = new HardConstraintChecker(model,
                model.getExclusionConstraints(),
                model.getErrorConstraints());

        assertEquals(otherSolver.isValid(new int[]{1, 0, 1}), solver.isValid(new int[]{1, 0, 1}));
        assertEquals(otherSolver.isValid(new int[]{0, 0, 1}), solver.isValid(new int[]{0, 0, 1}));
    }

    @Test
    void testCreateConstraintCheckerWithNegation() {
        final List<TupleList> errorTupleLists = new ArrayList<>();
        errorTupleLists.add(new TupleList(1, new int[]{0, 1}, Arrays.asList(new int[]{0, 0}, new int[]{1, 1})));

        final TestModel model = new TestModel(2, new int[]{2, 2, 2}, Collections.emptyList(), errorTupleLists);

        final ConstraintChecker solver = new HardConstraintCheckerFactory()
                .createConstraintCheckerWithNegation(model, errorTupleLists.get(0));
        final ConstraintChecker otherSolver = new HardConstraintChecker(model,
                model.getExclusionConstraints(),
                model.getErrorConstraints());

        assertEquals(otherSolver.isValid(new int[]{1, 0, 1}), !solver.isValid(new int[]{1, 0, 1}));
        assertEquals(otherSolver.isValid(new int[]{0, 0, 1}), !solver.isValid(new int[]{0, 0, 1}));
    }
}
