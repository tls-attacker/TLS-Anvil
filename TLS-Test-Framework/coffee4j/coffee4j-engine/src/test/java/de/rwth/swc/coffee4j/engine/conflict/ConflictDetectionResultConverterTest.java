package de.rwth.swc.coffee4j.engine.conflict;

import de.rwth.swc.coffee4j.engine.TestModel;
import de.rwth.swc.coffee4j.engine.TupleList;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertTrue;

class ConflictDetectionResultConverterTest {

    @Test
    void testConvertConflictSet() {
        final TestModel expandedTestModel = mock(TestModel.class);
        when(expandedTestModel.getForbiddenTupleLists()).thenReturn(Collections.emptyList());
        when(expandedTestModel.getErrorTupleLists()).thenReturn(Arrays.asList(
            new TupleList(10, new int[] {0}, Collections.singletonList(new int[] {2})),
            new TupleList(41, new int[] {0, 1}, Collections.singletonList(new int[] {0, 2})),
            new TupleList(51, new int[] {0, 1}, Collections.singletonList(new int[] {1, 2}))));

        final InternalConflictSet internalConflict = mock(InternalConflictSet.class);
        when(internalConflict.getConflictSet()).thenReturn(new int[] {10, 41, 51});

        final TestModelExpander expander = mock(TestModelExpander.class);
        when(expander.computeOriginalId(10)).thenReturn(1);
        when(expander.computeOriginalId(41)).thenReturn(4);
        when(expander.computeOriginalId(51)).thenReturn(5);

        final ConflictDetectionResultConverter converter = new ConflictDetectionResultConverter(expandedTestModel, expander);
        final ConflictSet conflictSet = converter.convertConflictSet(internalConflict);

        assertEquals(3, conflictSet.getConflictElements().size());
        assertTrue(conflictSet.getConflictElements().stream()
                .anyMatch(conflict ->
                        conflict.getConflictingConstraintId() == 1
                                && Arrays.equals(new int[] {0}, conflict.getInvolvedParameters())
                                && Arrays.equals(new int[] {2}, conflict.getConflictingValues()))
        );
        assertTrue(conflictSet.getConflictElements().stream()
                .anyMatch(conflict ->
                        conflict.getConflictingConstraintId() == 4
                                && Arrays.equals(new int[] {0, 1}, conflict.getInvolvedParameters())
                                && Arrays.equals(new int[] {0, 2}, conflict.getConflictingValues()))
        );
        assertTrue(conflictSet.getConflictElements().stream()
                .anyMatch(conflict ->
                        conflict.getConflictingConstraintId() == 5
                                && Arrays.equals(new int[] {0, 1}, conflict.getInvolvedParameters())
                                && Arrays.equals(new int[] {1, 2}, conflict.getConflictingValues()))
        );
    }

    @Test
    void testConvertConflictElement() {
        final TestModel expandedTestModel = mock(TestModel.class);
        when(expandedTestModel.getForbiddenTupleLists()).thenReturn(Collections.emptyList());
        when(expandedTestModel.getErrorTupleLists()).thenReturn(Arrays.asList(
                new TupleList(10, new int[] {0}, Collections.singletonList(new int[] {2})),
                new TupleList(41, new int[] {0, 1}, Collections.singletonList(new int[] {0, 2})),
                new TupleList(51, new int[] {0, 1}, Collections.singletonList(new int[] {1, 2}))));

        final InternalConflictSet internalConflict = mock(InternalConflictSet.class);
        when(internalConflict.getConflictSet()).thenReturn(new int[] {10, 41, 51});

        final TestModelExpander expander = mock(TestModelExpander.class);
        when(expander.computeOriginalId(10)).thenReturn(1);
        when(expander.computeOriginalId(41)).thenReturn(4);
        when(expander.computeOriginalId(51)).thenReturn(5);

        final ConflictDetectionResultConverter converter = new ConflictDetectionResultConverter(expandedTestModel, expander);

        ConflictElement conflict;

        conflict = converter.convertConflictElement(10);
        assertTrue(conflict.getConflictingConstraintId() == 1
                && Arrays.equals(new int[] {0}, conflict.getInvolvedParameters())
                && Arrays.equals(new int[] {2}, conflict.getConflictingValues()));

        conflict = converter.convertConflictElement(41);
        assertTrue(conflict.getConflictingConstraintId() == 4
                && Arrays.equals(new int[] {0, 1}, conflict.getInvolvedParameters())
                && Arrays.equals(new int[] {0, 2}, conflict.getConflictingValues()));

        conflict = converter.convertConflictElement(51);
        assertTrue(conflict.getConflictingConstraintId() == 5
                && Arrays.equals(new int[] {0, 1}, conflict.getInvolvedParameters())
                && Arrays.equals(new int[] {1, 2}, conflict.getConflictingValues()));
    }

    @Test
    void testConvertInconsistentBackground() {
        final TestModel testModel = mock(TestModel.class);
        when(testModel.getErrorTupleLists()).thenReturn(Arrays.asList(
                new TupleList(10, new int[] {0}, Collections.singletonList(new int[] {2})),
                new TupleList(41, new int[] {0, 1}, Collections.singletonList(new int[] {0, 2})),
                new TupleList(51, new int[] {0, 1}, Collections.singletonList(new int[] {1, 2}))));

        final InternalInconsistentBackground background = mock(InternalInconsistentBackground.class);
        when(background.getBackground()).thenReturn(new int[]{10, 41, 51});

        final TestModelExpander expander = mock(TestModelExpander.class);
        when(expander.computeOriginalId(10)).thenReturn(1);
        when(expander.computeOriginalId(41)).thenReturn(4);
        when(expander.computeOriginalId(51)).thenReturn(5);

        final ConflictDetectionResultConverter converter = new ConflictDetectionResultConverter(testModel, expander);
        final InconsistentBackground inconsistentBackground = converter.convertInconsistentBackground(background);

        assertEquals(3, inconsistentBackground.getConflictElements().size());

        assertTrue(inconsistentBackground.getConflictElements().stream()
                .anyMatch(conflict ->
                        conflict.getConflictingConstraintId() == 1
                                && Arrays.equals(new int[] {0}, conflict.getInvolvedParameters())
                                && Arrays.equals(new int[] {2}, conflict.getConflictingValues()))
        );
        assertTrue(inconsistentBackground.getConflictElements().stream()
                .anyMatch(conflict ->
                        conflict.getConflictingConstraintId() == 4
                                && Arrays.equals(new int[] {0, 1}, conflict.getInvolvedParameters())
                                && Arrays.equals(new int[] {0, 2}, conflict.getConflictingValues()))
        );
        assertTrue(inconsistentBackground.getConflictElements().stream()
                .anyMatch(conflict ->
                        conflict.getConflictingConstraintId() == 5
                                && Arrays.equals(new int[] {0, 1}, conflict.getInvolvedParameters())
                                && Arrays.equals(new int[] {1, 2}, conflict.getConflictingValues()))
        );
    }

    @Test
    void testConvertDiagnosisElement() {
        final TestModel expandedTestModel = mock(TestModel.class);
        when(expandedTestModel.getForbiddenTupleLists()).thenReturn(Collections.emptyList());
        when(expandedTestModel.getErrorTupleLists()).thenReturn(Arrays.asList(
                new TupleList(10, new int[] {0}, Collections.singletonList(new int[] {2})),
                new TupleList(41, new int[] {0, 1}, Collections.singletonList(new int[] {0, 2})),
                new TupleList(51, new int[] {0, 1}, Collections.singletonList(new int[] {1, 2}))));

        final TestModelExpander expander = mock(TestModelExpander.class);
        when(expander.computeOriginalId(10)).thenReturn(1);
        when(expander.computeOriginalId(41)).thenReturn(4);
        when(expander.computeOriginalId(51)).thenReturn(5);

        final ConflictDetectionResultConverter converter = new ConflictDetectionResultConverter(expandedTestModel, expander);
        final DiagnosisElement diagnosisElement = converter.convertDiagnosisElement(10);

        assertTrue(diagnosisElement.getDiagnosedConstraintId() == 1
                && Arrays.equals(new int[] {0,}, diagnosisElement.getInvolvedParameters())
                && Arrays.equals(new int[] {2}, diagnosisElement.getConflictingValues()));
    }

    @Test
    void testConvertDiagnosis() {
        final TestModel expandedTestModel = mock(TestModel.class);
        when(expandedTestModel.getForbiddenTupleLists()).thenReturn(Collections.emptyList());
        when(expandedTestModel.getErrorTupleLists()).thenReturn(Arrays.asList(
                new TupleList(10, new int[] {0}, Collections.singletonList(new int[] {2})),
                new TupleList(41, new int[] {0, 1}, Collections.singletonList(new int[] {0, 2})),
                new TupleList(51, new int[] {0, 1}, Collections.singletonList(new int[] {1, 2}))));

        final TestModelExpander expander = mock(TestModelExpander.class);
        when(expander.computeOriginalId(10)).thenReturn(1);
        when(expander.computeOriginalId(41)).thenReturn(4);
        when(expander.computeOriginalId(51)).thenReturn(5);

        final ConflictDetectionResultConverter converter = new ConflictDetectionResultConverter(expandedTestModel, expander);

        final ConflictSet conflictSet = mock(ConflictSet.class);

        final DiagnosisSet diagnosis = converter.convertDiagnosisSet(new int[] { 10, 41, 51});

        assertTrue(diagnosis.getDiagnosisElements().stream().anyMatch(diagnosisElement ->
                        diagnosisElement.getDiagnosedConstraintId() == 1
                                && Arrays.equals(new int[]{0}, diagnosisElement.getInvolvedParameters())
                                && Arrays.equals(new int[]{2}, diagnosisElement.getConflictingValues())
                )
        );
        assertTrue(diagnosis.getDiagnosisElements().stream().anyMatch(diagnosisElement ->
                        diagnosisElement.getDiagnosedConstraintId() == 4
                                && Arrays.equals(new int[]{0,1}, diagnosisElement.getInvolvedParameters())
                                && Arrays.equals(new int[]{0,2}, diagnosisElement.getConflictingValues())
                )
        );
        assertTrue(diagnosis.getDiagnosisElements().stream().anyMatch(diagnosisElement ->
                        diagnosisElement.getDiagnosedConstraintId() == 5
                                && Arrays.equals(new int[]{0,1}, diagnosisElement.getInvolvedParameters())
                                && Arrays.equals(new int[]{1,2}, diagnosisElement.getConflictingValues())
                )
        );
    }

    @Test
    void testConvertDiagnosisSet() {
        final TestModel expandedTestModel = mock(TestModel.class);
        when(expandedTestModel.getForbiddenTupleLists()).thenReturn(Collections.emptyList());
        when(expandedTestModel.getErrorTupleLists()).thenReturn(Arrays.asList(
                new TupleList(10, new int[] {0}, Collections.singletonList(new int[] {2})),
                new TupleList(41, new int[] {0, 1}, Collections.singletonList(new int[] {0, 2})),
                new TupleList(51, new int[] {0, 1}, Collections.singletonList(new int[] {1, 2}))));

        final TestModelExpander expander = mock(TestModelExpander.class);
        when(expander.computeOriginalId(10)).thenReturn(1);
        when(expander.computeOriginalId(41)).thenReturn(4);
        when(expander.computeOriginalId(51)).thenReturn(5);

        final ConflictDetectionResultConverter converter = new ConflictDetectionResultConverter(expandedTestModel, expander);

        final InternalConflictSet internalConflict = mock(InternalConflictSet.class);
        when(internalConflict.getConflictSet()).thenReturn(new int[] {10, 41, 51});

        final InternalDiagnosisSets internalDiagnosis = mock(InternalDiagnosisSets.class);
        when(internalDiagnosis.getRootConflictSet()).thenReturn(internalConflict);
        when(internalDiagnosis.getDiagnosisSets()).thenReturn(new int[][]{ {10}, {41}, {51} });

        final DiagnosisSets diagnosisSets = converter.convertDiagnosisSets(internalDiagnosis);

        assertEquals(3, diagnosisSets.getDiagnosisSets().size());
        assertTrue(diagnosisSets.getDiagnosisSets().stream().anyMatch(diagnosisSet -> diagnosisSet.getDiagnosisElements().stream()
                                .anyMatch(element -> element.getDiagnosedConstraintId() == 1
                                        && Arrays.equals(new int[]{0}, element.getInvolvedParameters())
                                        && Arrays.equals(new int[]{2}, element.getConflictingValues()))));
        assertTrue(diagnosisSets.getDiagnosisSets().stream().anyMatch(diagnosisSet -> diagnosisSet.getDiagnosisElements().stream()
                .anyMatch(element -> element.getDiagnosedConstraintId() == 4
                        && Arrays.equals(new int[]{0, 1}, element.getInvolvedParameters())
                        && Arrays.equals(new int[]{0, 2}, element.getConflictingValues()))));
        assertTrue(diagnosisSets.getDiagnosisSets().stream().anyMatch(diagnosisSet -> diagnosisSet.getDiagnosisElements().stream()
                .anyMatch(element -> element.getDiagnosedConstraintId() == 5
                        && Arrays.equals(new int[]{0, 1}, element.getInvolvedParameters())
                        && Arrays.equals(new int[]{1, 2}, element.getConflictingValues()))));
    }
}
