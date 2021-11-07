package de.rwth.swc.coffee4j.engine.constraint;

import de.rwth.swc.coffee4j.engine.TestModel;
import de.rwth.swc.coffee4j.engine.TupleList;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SoftConstraintCheckerTest {

    private static final TestModel MODEL = new TestModel(2,
            new int[]{2, 2, 2},
            Collections.emptyList(),
            Arrays.asList(
                    new TupleList(1, new int[]{0, 1},   Arrays.asList(new int[]{0, 0}, new int[]{1, 1})),
                    new TupleList(2, new int[]{0, 1},   Arrays.asList(new int[]{0, 0}, new int[]{1, 1})),
                    new TupleList(3, new int[]{2},      Collections.singletonList(new int[]{1}))));

    private static ConstraintChecker createSoftConstraintsChecker(int threshold) {
        return new SoftConstraintChecker(
                MODEL,
                Collections.emptyList(),
                MODEL.getErrorConstraints(),
                threshold);
    }

    @Test
    void checkValidWithoutConflict() {
        final ConstraintChecker checker = createSoftConstraintsChecker(0);

        assertTrue(checker.isValid(new int[]{1, 0, 0}));
    }

    @Test
    void checkInvalidWith1Conflict() {
        final ConstraintChecker checker = createSoftConstraintsChecker(0);

        assertFalse(checker.isValid(new int[]{0, 0, 0}));
        assertFalse(checker.isValid(new int[]{1, 0, 1}));
    }

    @Test
    void checkValidWith1Conflict() {
        final ConstraintChecker checker = createSoftConstraintsChecker(1);

        assertTrue(checker.isValid(new int[]{1, 0, 1}));
    }

    @Test
    void checkValidWith2Conflicts() {
        final ConstraintChecker checker = createSoftConstraintsChecker(2);

        assertTrue(checker.isValid(new int[]{0, 0, 0}));
    }

    @Test
    void checkValidWith3Conflicts() {
        final ConstraintChecker checker = createSoftConstraintsChecker(3);

        assertTrue(checker.isValid(new int[]{0, 0, 1}));
    }
}
