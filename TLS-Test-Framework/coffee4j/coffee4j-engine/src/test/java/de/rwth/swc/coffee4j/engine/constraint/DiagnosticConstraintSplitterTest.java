package de.rwth.swc.coffee4j.engine.constraint;

import de.rwth.swc.coffee4j.engine.TestModel;
import de.rwth.swc.coffee4j.engine.TupleList;
import de.rwth.swc.coffee4j.engine.conflict.InternalConflictSet;
import de.rwth.swc.coffee4j.engine.conflict.InternalDiagnosisSets;
import de.rwth.swc.coffee4j.engine.conflict.InternalMissingInvalidTuple;
import org.apache.commons.lang3.tuple.Pair;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;

class DiagnosticConstraintSplitterTest {

    private static final TestModel MODEL = new TestModel(2,
            new int[]{3, 3, 3},
            Collections.emptyList(),
            Arrays.asList(
                    new TupleList(1, new int[]{0, 1},   Arrays.asList(new int[]{0, 0}, new int[]{1, 1})),
                    new TupleList(2, new int[]{0, 1},   Arrays.asList(new int[]{0, 0}, new int[]{1, 1})),
                    new TupleList(3, new int[]{2},      Collections.singletonList(new int[]{1}))));

    @Test
    void testNullTestModel() {
        assertThrows(NullPointerException.class,
                ()-> new DiagnosticConstraintSplitter().splitConstraints(
                        null, MODEL.getErrorTupleLists().get(0), Collections.emptyList()));
    }

    @Test
    void testNullToBeNegated() {
        assertThrows(IllegalArgumentException.class,
                ()-> new DiagnosticConstraintSplitter().splitConstraints(
                        MODEL,
                        new TupleList(4, new int[]{2},      Collections.singletonList(new int[]{1})),
                        Collections.emptyList()));
    }

    @Test
    void testUnknownToBeNegated() {
        assertThrows(NullPointerException.class,
                ()-> new DiagnosticConstraintSplitter().splitConstraints(
                        MODEL, null, Collections.emptyList()));
    }

    @Test
    void testNullMissingInvalidTuples() {
        assertThrows(NullPointerException.class,
                ()-> new DiagnosticConstraintSplitter().splitConstraints(
                        MODEL, MODEL.getErrorTupleLists().get(0), null));
    }

    @Test
    void testToBeNegatedIsHardConstraint() {
        final DiagnosticConstraintSplitter splitter = new DiagnosticConstraintSplitter();

        final Pair<List<Constraint>, List<Constraint>> pair = splitter
                .splitConstraints(MODEL, MODEL.getErrorTupleLists().get(2), Collections.emptyList());
        final List<Constraint> hardConstraints = pair.getLeft();

        assertTrue(hardConstraints.stream()
                .anyMatch(constraint ->
                        constraint.getTupleList().getId() == MODEL.getErrorTupleLists().get(2).getId()));
    }

    @Test
    void testSplitConstraints() {
        final DiagnosticConstraintSplitter splitter = new DiagnosticConstraintSplitter();

        final List<InternalMissingInvalidTuple> mits = Arrays.asList(
                new InternalMissingInvalidTuple(2, new int[]{0, 1}, new int[]{0, 0},
                        new InternalDiagnosisSets(mock(InternalConflictSet.class), new int[][] { new int[] {2} })),
                new InternalMissingInvalidTuple(2, new int[]{0, 1}, new int[]{1, 1},
                        new InternalDiagnosisSets(mock(InternalConflictSet.class), new int[][] { new int[] {2} }))
        );

        final Pair<List<Constraint>, List<Constraint>> pair = splitter
                .splitConstraints(MODEL, MODEL.getErrorTupleLists().get(0), mits);

        final List<Constraint> hardConstraint = pair.getLeft();
        final List<Constraint> softConstraint = pair.getRight();

        assertEquals(2, hardConstraint.size());
        assertTrue(hardConstraint.stream().anyMatch(constraint -> constraint.getTupleList().getId() == 1));
        assertTrue(hardConstraint.stream().anyMatch(constraint -> constraint.getTupleList().getId() == 3));
        assertEquals(1, softConstraint.size());
        assertTrue(softConstraint.stream().anyMatch(constraint -> constraint.getTupleList().getId() == 2));
    }

    @Test
    void testSplitConstraintsWithoutMissingInvalidTuples() {
        final DiagnosticConstraintSplitter splitter = new DiagnosticConstraintSplitter();

        final Pair<List<Constraint>, List<Constraint>> pair = splitter
                .splitConstraints(MODEL, MODEL.getErrorTupleLists().get(2), Collections.emptyList());

        final List<Constraint> hardConstraint = pair.getLeft();
        final List<Constraint> softConstraint = pair.getRight();

        assertTrue(hardConstraint.stream().anyMatch(constraint -> constraint.getTupleList().getId() == 1));
        assertTrue(hardConstraint.stream().anyMatch(constraint -> constraint.getTupleList().getId() == 2));
        assertTrue(hardConstraint.stream().anyMatch(constraint -> constraint.getTupleList().getId() == 3));
        assertTrue(softConstraint.isEmpty());
    }
}
