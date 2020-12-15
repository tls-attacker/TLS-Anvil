package de.rwth.swc.coffee4j.engine.constraint;

import de.rwth.swc.coffee4j.engine.TestModel;
import de.rwth.swc.coffee4j.engine.TupleList;
import de.rwth.swc.coffee4j.engine.conflict.InternalConflictSet;
import de.rwth.swc.coffee4j.engine.conflict.InternalDiagnosisSets;
import de.rwth.swc.coffee4j.engine.conflict.InternalMissingInvalidTuple;
import it.unimi.dsi.fastutil.objects.Object2IntMap;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static de.rwth.swc.coffee4j.engine.util.IntArrayWrapper.wrap;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;

class DiagnosticConstraintThresholdComputerTest {

    private static final TestModel MODEL = new TestModel(2,
            new int[]{3, 3, 3},
            Collections.emptyList(),
            Arrays.asList(
                    new TupleList(1, new int[]{0, 1},   Arrays.asList(new int[]{0, 0}, new int[]{1, 1})),
                    new TupleList(2, new int[]{0, 1},   Arrays.asList(new int[]{0, 0}, new int[]{1, 1})),
                    new TupleList(3, new int[]{2},      Collections.singletonList(new int[]{1}))));

    @Test
    void testComputeSingleThresholds() {
        final DiagnosticConstraintThresholdComputer computer = new DiagnosticConstraintThresholdComputer();

        final List<InternalMissingInvalidTuple> mits = Arrays.asList(
                new InternalMissingInvalidTuple(1, new int[]{0, 1}, new int[]{0, 0},
                        new InternalDiagnosisSets(mock(InternalConflictSet.class), new int[][] { new int[] {2} })),
                new InternalMissingInvalidTuple(1, new int[]{0, 1}, new int[]{1, 1},
                        new InternalDiagnosisSets(mock(InternalConflictSet.class), new int[][] { new int[] {2} })));

        final Object2IntMap map = computer.computeThresholds(MODEL.getErrorTupleLists().get(0), mits);

        assertEquals(1, map.getInt(wrap(new int[]{0, 0})));
        assertEquals(1, map.getInt(wrap(new int[]{1, 1})));
    }

    @Test
    void testComputeThresholds() {
        final DiagnosticConstraintThresholdComputer computer = new DiagnosticConstraintThresholdComputer();

        final List<InternalMissingInvalidTuple> mits = Arrays.asList(
                new InternalMissingInvalidTuple(1, new int[]{0, 1}, new int[]{0, 0},
                        new InternalDiagnosisSets(mock(InternalConflictSet.class), new int[][] { new int[] {2} })),
                new InternalMissingInvalidTuple(1, new int[]{0, 1}, new int[]{1, 1},
                        new InternalDiagnosisSets(mock(InternalConflictSet.class), new int[][] { new int[] {2, 3} })));

        final Object2IntMap map = computer.computeThresholds(MODEL.getErrorTupleLists().get(0), mits);

        assertEquals(1, map.getInt(wrap(new int[]{0, 0})));
        assertEquals(2, map.getInt(wrap(new int[]{1, 1})));
    }

    @Test
    void testComputeThresholdsWithoutMissingInvalidTuples() {
        final DiagnosticConstraintThresholdComputer computer = new DiagnosticConstraintThresholdComputer();

        final List<InternalMissingInvalidTuple> mits = Collections.emptyList();
        final Object2IntMap map = computer.computeThresholds(MODEL.getErrorTupleLists().get(2), mits);

        assertEquals(0, map.getInt(wrap(new int[]{0, 0})));
        assertEquals(0, map.getInt(wrap(new int[]{1, 1})));

    }
}
