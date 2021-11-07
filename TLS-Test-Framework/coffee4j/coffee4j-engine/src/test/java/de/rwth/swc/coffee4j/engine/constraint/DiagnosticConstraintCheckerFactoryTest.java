package de.rwth.swc.coffee4j.engine.constraint;

import de.rwth.swc.coffee4j.engine.TestModel;
import de.rwth.swc.coffee4j.engine.TupleList;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.*;

class DiagnosticConstraintCheckerFactoryTest {

    static final TestModel MODEL = new TestModel(2,
            new int[]{3, 3, 3},
            Collections.emptyList(),
            Arrays.asList(
                    new TupleList(1, new int[]{0},    Collections.singletonList(new int[]{2})),
                    new TupleList(2, new int[]{1},    Collections.singletonList(new int[]{2})),
                    new TupleList(3, new int[]{2},    Collections.singletonList(new int[]{2})),
                    new TupleList(4, new int[]{0, 1}, Arrays.asList(new int[]{0, 1}, new int[]{0, 2})),
                    new TupleList(5, new int[]{0, 1}, Arrays.asList(new int[]{1, 0}, new int[]{1, 2}))));

    @Test
    void testCreateConstraintCheckerWithNegationWithoutConflict() {

        final DiagnosticConstraintCheckerFactory factory = new DiagnosticConstraintCheckerFactory();
        final ConstraintChecker checker = factory.createConstraintCheckerWithNegation(MODEL, MODEL.getErrorTupleLists().get(2));

        assertTrue(checker instanceof HardConstraintChecker);
    }

    @Test
    void testCreateConstraintCheckerWithNegationWithConflict() {
        final DiagnosticConstraintCheckerFactory factory = new DiagnosticConstraintCheckerFactory();
        final ConstraintChecker checker = factory.createConstraintCheckerWithNegation(MODEL, MODEL.getErrorTupleLists().get(3));

        assertFalse(checker.isDualValid(new int[]{0, 1}, new int[]{0, 0}));
        assertFalse(checker.isDualValid(new int[]{0, 2}, new int[]{0, 2}));
        assertTrue(checker.isDualValid(new int[]{0, 1}, new int[]{0, 1}));
        assertTrue(checker.isDualValid(new int[]{0, 1}, new int[]{0, 2}));
    }

    @Test
    void testCreateConstraintChecker() {
        assertThrows(UnsupportedOperationException.class,
                () -> new DiagnosticConstraintCheckerFactory().createConstraintChecker(null));
    }
}
