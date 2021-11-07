package de.rwth.swc.coffee4j.engine.constraint;

import de.rwth.swc.coffee4j.engine.TestModel;
import de.rwth.swc.coffee4j.engine.TupleList;
import de.rwth.swc.coffee4j.engine.util.IntArrayWrapper;
import it.unimi.dsi.fastutil.objects.Object2IntArrayMap;
import it.unimi.dsi.fastutil.objects.Object2IntMap;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static de.rwth.swc.coffee4j.engine.util.IntArrayWrapper.wrap;
import static org.junit.jupiter.api.Assertions.*;

class DiagnosticConstraintCheckerTest {

    @Test
    void testDiagnosticConstraintChecker() {
        final TestModel MODEL = new TestModel(2,
                new int[]{2, 2, 2},
                Collections.emptyList(),
                Arrays.asList(
                        new TupleList(1, new int[]{0, 1}, Arrays.asList(new int[]{1, 0}, new int[]{0, 1})),
                        new TupleList(2, new int[]{0, 1}, Collections.singletonList(new int[]{0, 0})),
                        new TupleList(3, new int[]{2},    Collections.singletonList(new int[]{1}))));

        final List<Constraint> hardConstraints = Arrays.asList(
                MODEL.getErrorConstraints().get(0),
                MODEL.getErrorConstraints().get(2));

        final List<Constraint> softConstraints = Collections.singletonList(
                MODEL.getErrorConstraints().get(1));

        final Object2IntMap<IntArrayWrapper> thresholds = new Object2IntArrayMap<>();
        thresholds.put(wrap(new int[] {0, 0}), 1);
        thresholds.put(wrap(new int[] {1, 1}), 0);

        final ConstraintChecker checker = new DiagnosticConstraintChecker(
                MODEL, MODEL.getErrorTupleLists().get(0), hardConstraints, softConstraints, thresholds);

        assertTrue(checker.isDualValid(new int[]{0, 1}, new int[] {0, 0}));
        assertTrue(checker.isDualValid(new int[]{0, 1}, new int[] {1, 1}));
        assertFalse(checker.isDualValid(new int[]{0, 1}, new int[] {1, 0}));
        assertFalse(checker.isDualValid(new int[]{0, 1}, new int[] {0, 1}));
    }

    @Test
    void testDiagnosticConstraintCheckerWithExample1() { /* not over-constrained */
        final TestModel MODEL = new TestModel(2,
                new int[]{3, 3, 3},
                Collections.emptyList(),
                Arrays.asList(
                        new TupleList(1, new int[]{0}, List.of(new int[]{2})),
                        new TupleList(2, new int[]{1}, List.of(new int[]{2})),
                        new TupleList(3, new int[]{2}, List.of(new int[]{0}, new int[]{1})), /* negated */
                        new TupleList(4, new int[]{0, 1}, List.of(new int[]{0, 1}, new int[]{0, 2})),
                        new TupleList(5, new int[]{0, 1}, List.of(new int[]{1, 0}, new int[]{1, 2}))));

        final List<Constraint> hardConstraints = Arrays.asList(
                MODEL.getErrorConstraints().get(0),
                MODEL.getErrorConstraints().get(1),
                MODEL.getErrorConstraints().get(2),
                MODEL.getErrorConstraints().get(3),
                MODEL.getErrorConstraints().get(4));

        final List<Constraint> softConstraints = Collections.emptyList();

        final Object2IntMap<IntArrayWrapper> thresholds = new Object2IntArrayMap<>();
        thresholds.put(wrap(new int[] {2}), 0);

        final ConstraintChecker checker = new DiagnosticConstraintChecker(
                MODEL, MODEL.getErrorTupleLists().get(2), hardConstraints, softConstraints, thresholds);

        assertTrue(checker.isDualValid(new int[]{2}, new int[] {2}));
        assertFalse(checker.isDualValid(new int[]{2}, new int[] {0}));
        assertFalse(checker.isDualValid(new int[]{2}, new int[] {1}));
        assertTrue(checker.isDualValid(new int[]{0, 1, 2}, new int[] {0, 0, 2}));
        assertFalse(checker.isDualValid(new int[]{0, 1, 2}, new int[] {0, 1, 2}));
        assertTrue(checker.isDualValid(new int[]{0, 1}, new int[] {0, 0}));
        assertTrue(checker.isDualValid(new int[]{0, 1}, new int[] {1, 1}));
        assertFalse(checker.isDualValid(new int[]{0, 1}, new int[] {1, 0}));
        assertFalse(checker.isDualValid(new int[]{0, 1}, new int[] {0, 1}));
    }

    @Test
    void testDiagnosticConstraintCheckerWithExample2() { /* implicit conflict */
        final TestModel MODEL = new TestModel(2,
                new int[]{3, 3, 3},
                Collections.emptyList(),
                Arrays.asList(
                        new TupleList(1, new int[]{0}, List.of(new int[]{0}, new int[]{1})), /* negated */
                        new TupleList(2, new int[]{1}, List.of(new int[]{2})),
                        new TupleList(3, new int[]{2}, List.of(new int[]{2})),
                        new TupleList(4, new int[]{0, 1}, List.of(new int[]{0, 1}, new int[]{0, 2})),
                        new TupleList(5, new int[]{0, 1}, List.of(new int[]{1, 0}, new int[]{1, 2}))));

        final List<Constraint> hardConstraints = List.of(
                MODEL.getErrorConstraints().get(0),
                MODEL.getErrorConstraints().get(1),
                MODEL.getErrorConstraints().get(2));

        final List<Constraint> softConstraints = List.of(
                MODEL.getErrorConstraints().get(3),
                MODEL.getErrorConstraints().get(4));

        final Object2IntMap<IntArrayWrapper> thresholds = new Object2IntArrayMap<>();
        thresholds.put(wrap(new int[] {2}), 1);

        final ConstraintChecker checker = new DiagnosticConstraintChecker(
                MODEL, MODEL.getErrorTupleLists().get(0), hardConstraints, softConstraints, thresholds);

        assertFalse(checker.isDualValid(new int[]{0, 1}, new int[] {0, 0}));
        assertFalse(checker.isDualValid(new int[]{0, 1}, new int[] {1, 1}));
        assertFalse(checker.isDualValid(new int[]{0, 1}, new int[] {0, 1}));
        assertFalse(checker.isDualValid(new int[]{0, 1}, new int[] {1, 0}));
        assertTrue(checker.isDualValid(new int[]{0, 1}, new int[] {2, 0}));
        assertTrue(checker.isDualValid(new int[]{0, 1}, new int[] {2, 1}));
    }

    @Test
    void testDiagnosticConstraintCheckerWithExample3() {
        final TestModel MODEL = new TestModel(2,
                new int[]{3, 3, 3},
                Collections.emptyList(),
                Arrays.asList(
                        new TupleList(1, new int[]{0}, List.of(new int[]{2})),
                        new TupleList(2, new int[]{1}, List.of(new int[]{2})),
                        new TupleList(3, new int[]{2}, List.of(new int[]{2})),
                        new TupleList(4, new int[]{0, 1}, List.of(new int[]{0, 0}, new int[]{1, 1})), /* negated */
                        new TupleList(5, new int[]{0, 1}, List.of(new int[]{1, 0}, new int[]{1, 2}))));

        final List<Constraint> hardConstraints = List.of(
                MODEL.getErrorConstraints().get(0),
                MODEL.getErrorConstraints().get(2),
                MODEL.getErrorConstraints().get(3),
                MODEL.getErrorConstraints().get(4));

        final List<Constraint> softConstraints = List.of(
                MODEL.getErrorConstraints().get(1));

        final Object2IntMap<IntArrayWrapper> thresholds = new Object2IntArrayMap<>();
        thresholds.put(wrap(new int[] {0, 1}), 0);
        thresholds.put(wrap(new int[] {0, 2}), 1);

        final ConstraintChecker checker = new DiagnosticConstraintChecker(
                MODEL, MODEL.getErrorTupleLists().get(3), hardConstraints, softConstraints, thresholds);

        assertFalse(checker.isDualValid(new int[]{0, 1}, new int[] {0, 0}));
        assertFalse(checker.isDualValid(new int[]{0, 1}, new int[] {1, 1}));
        assertTrue(checker.isDualValid(new int[]{0, 1}, new int[] {0, 1}));
        assertTrue(checker.isDualValid(new int[]{0, 1}, new int[] {0, 2}));
        assertTrue(checker.isDualValid(new int[]{0, 1, 2}, new int[] {0, 1, 0}));
        assertFalse(checker.isDualValid(new int[]{0, 1, 2}, new int[] {0, 1, 2}));
        assertTrue(checker.isDualValid(new int[]{0, 1, 2}, new int[] {0, 2, 0}));
        assertFalse(checker.isDualValid(new int[]{0, 1, 2}, new int[] {0, 2, 2}));
    }
}
