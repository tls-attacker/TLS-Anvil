package de.rwth.swc.coffee4j.engine.conflict;

import de.rwth.swc.coffee4j.engine.TestModel;
import de.rwth.swc.coffee4j.engine.TupleList;
import de.rwth.swc.coffee4j.engine.conflict.diagnosis.ExhaustiveConflictDiagnostician;
import de.rwth.swc.coffee4j.engine.conflict.explanation.QuickConflictExplainer;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static de.rwth.swc.coffee4j.engine.AssertUtils.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.*;
import static org.testng.Assert.assertTrue;

class ConflictDetectionManagerTest {

    @Test
    void testMinimalConflictExplanation() {
        final ConflictDetectionConfiguration configuration = new ConflictDetectionConfiguration(
                true,
                false,
                true,
                QuickConflictExplainer.class,
                false,
                ExhaustiveConflictDiagnostician.class);

        final List<TupleList> errorTupleLists = new ArrayList<>();
        errorTupleLists.add(new TupleList(1, new int[]{0, 1}, Arrays.asList(new int[]{1, 0}, new int[]{2, 0}, new int[]{0, 1}, new int[]{0, 2})));
        errorTupleLists.add(new TupleList(2, new int[]{0, 1}, Arrays.asList(new int[]{0, 1}, new int[]{2, 1}, new int[]{1, 0}, new int[]{1, 2})));
        errorTupleLists.add(new TupleList(3, new int[]{2}, Collections.singletonList(new int[]{2})));

        final TestModel model = new TestModel(2, new int[]{3, 3, 3}, Collections.emptyList(), errorTupleLists);

        final ConflictDetectionManager manager = new ConflictDetectionManager(configuration, model);
        final List<MissingInvalidTuple> mits = manager.detectMissingInvalidTuples();

        assertEquals(4, mits.size());

        assertTrue(mits.stream().anyMatch(mit -> mit.getNegatedErrorConstraintId() == 1
                && Arrays.equals(new int[]{0, 1}, mit.getInvolvedParameters())
                && Arrays.equals(new int[]{1, 0}, mit.getMissingValues())
                && mit.getExplanation() instanceof ConflictSet
                && ((ConflictSet) mit.getExplanation()).getConflictElements().size() == 1
                && ((ConflictSet) mit.getExplanation()).getConflictElements().get(0).getConflictingConstraintId() == 2
                && Arrays.equals(new int[] {0, 1} ,((ConflictSet) mit.getExplanation()).getConflictElements().get(0).getInvolvedParameters())
                && Arrays.equals(new int[] {1, 0} ,((ConflictSet) mit.getExplanation()).getConflictElements().get(0).getConflictingValues())
        ));

        assertTrue(mits.stream().anyMatch(mit -> mit.getNegatedErrorConstraintId() == 1
                && Arrays.equals(new int[]{0, 1}, mit.getInvolvedParameters())
                && Arrays.equals(new int[]{0, 1}, mit.getMissingValues())
                && mit.getExplanation() instanceof ConflictSet
                && ((ConflictSet) mit.getExplanation()).getConflictElements().size() == 1
                && ((ConflictSet) mit.getExplanation()).getConflictElements().get(0).getConflictingConstraintId() == 2
                && Arrays.equals(new int[] {0, 1} ,((ConflictSet) mit.getExplanation()).getConflictElements().get(0).getInvolvedParameters())
                && Arrays.equals(new int[] {0, 1} ,((ConflictSet) mit.getExplanation()).getConflictElements().get(0).getConflictingValues())
        ));

        assertTrue(mits.stream().anyMatch(mit -> mit.getNegatedErrorConstraintId() == 2
                && Arrays.equals(new int[]{0, 1}, mit.getInvolvedParameters())
                && Arrays.equals(new int[]{1, 0}, mit.getMissingValues())
                && mit.getExplanation() instanceof ConflictSet
                && ((ConflictSet) mit.getExplanation()).getConflictElements().size() == 1
                && ((ConflictSet) mit.getExplanation()).getConflictElements().get(0).getConflictingConstraintId() == 1
                && Arrays.equals(new int[] {0, 1} ,((ConflictSet) mit.getExplanation()).getConflictElements().get(0).getInvolvedParameters())
                && Arrays.equals(new int[] {1, 0} ,((ConflictSet) mit.getExplanation()).getConflictElements().get(0).getConflictingValues())
        ));

        assertTrue(mits.stream().anyMatch(mit -> mit.getNegatedErrorConstraintId() == 2
                && Arrays.equals(new int[]{0, 1}, mit.getInvolvedParameters())
                && Arrays.equals(new int[]{0, 1}, mit.getMissingValues())
                && mit.getExplanation() instanceof ConflictSet
                && ((ConflictSet) mit.getExplanation()).getConflictElements().size() == 1
                && ((ConflictSet) mit.getExplanation()).getConflictElements().get(0).getConflictingConstraintId() == 1
                && Arrays.equals(new int[] {0, 1} ,((ConflictSet) mit.getExplanation()).getConflictElements().get(0).getInvolvedParameters())
                && Arrays.equals(new int[] {0, 1} ,((ConflictSet) mit.getExplanation()).getConflictElements().get(0).getConflictingValues())
        ));
    }

    @Test
    void testNoConflictExplanation() {
        final ConflictDetectionConfiguration configuration = new ConflictDetectionConfiguration(
                true,
                false,
                true,
                QuickConflictExplainer.class,
                true,
                ExhaustiveConflictDiagnostician.class);

        final List<TupleList> errorTupleLists = new ArrayList<>();
        errorTupleLists.add(new TupleList(1, new int[]{0, 1}, Arrays.asList(new int[]{1, 0}, new int[]{2, 0}, new int[]{0, 1}, new int[]{0, 2})));
        errorTupleLists.add(new TupleList(2, new int[]{2}, Collections.singletonList(new int[]{2})));

        final TestModel model = new TestModel(2, new int[]{3, 3, 3}, Collections.emptyList(), errorTupleLists);

        final ConflictDetectionManager manager = new ConflictDetectionManager(configuration, model);
        final List<MissingInvalidTuple> mits = manager.detectMissingInvalidTuples();

        assertEquals(0, mits.size());
    }

    @Test
    void testCTA2019SoundExample() {
        final ConflictDetectionConfiguration configuration = new ConflictDetectionConfiguration(
                true,
                false,
                true,
                QuickConflictExplainer.class,
                true,
                ExhaustiveConflictDiagnostician.class);

        final List<TupleList> errorTupleLists = new ArrayList<>();
        errorTupleLists.add(new TupleList(1, new int[]{0}, Collections.singletonList(new int[]{2})));               // [Title:123]
        errorTupleLists.add(new TupleList(2, new int[]{1}, Collections.singletonList(new int[]{2})));               // [GivenName:123]
        errorTupleLists.add(new TupleList(3, new int[]{2}, Collections.singletonList(new int[]{2})));               // [FamilyName:123]
        errorTupleLists.add(new TupleList(4, new int[]{0, 1}, Collections.singletonList(new int[]{0, 1})));         // [Title:Mr,GivenName:Jane], [Title:Mr,GivenName:123]
        errorTupleLists.add(new TupleList(5, new int[]{0, 1}, Collections.singletonList(new int[]{1, 0})));         // [Title:Mrs,GivenName:John], [Title:Mrs,GivenName:123]

        final TestModel model = new TestModel(2, new int[]{3, 3, 3}, Collections.emptyList(), errorTupleLists);

        final ConflictDetectionManager manager = new ConflictDetectionManager(configuration, model);
        final List<MissingInvalidTuple> mits = manager.detectMissingInvalidTuples();

        assertEquals(0, mits.size());
    }

    @Test
    void testCTA2019ExampleWithCorrectConstraint() {
        final ConflictDetectionConfiguration configuration = new ConflictDetectionConfiguration(
                true,
                false,
                true,
                QuickConflictExplainer.class,
                true,
                ExhaustiveConflictDiagnostician.class);

        final List<TupleList> errorTupleLists = new ArrayList<>();
        errorTupleLists.add(new TupleList(1, new int[]{0}, Collections.singletonList(new int[]{2})));                       // [Title:123]
        errorTupleLists.add(new TupleList(2, new int[]{1}, Collections.singletonList(new int[]{2}), true));   // [GivenName:123]
        errorTupleLists.add(new TupleList(3, new int[]{2}, Collections.singletonList(new int[]{2})));                       // [FamilyName:123]
        errorTupleLists.add(new TupleList(4, new int[]{0, 1}, Arrays.asList(new int[]{0, 1}, new int[]{0, 2})));            // [Title:Mr,GivenName:Jane], [Title:Mr,GivenName:123]
        errorTupleLists.add(new TupleList(5, new int[]{0, 1}, Arrays.asList(new int[]{1, 0}, new int[]{1, 2})));            // [Title:Mrs,GivenName:John], [Title:Mrs,GivenName:123]

        final TestModel model = new TestModel(2, new int[]{3, 3, 3}, Collections.emptyList(), errorTupleLists);

        final ConflictDetectionManager manager = new ConflictDetectionManager(configuration, model);
        final List<MissingInvalidTuple> mits = manager.detectMissingInvalidTuples();

        MissingInvalidTuple mit;
        DiagnosisSets diagnosisSets;
        DiagnosisSet diagnosisSet;

        // getNegatedErrorConstraintId() == 2
        mit = mits.stream().filter(tuple -> tuple.getNegatedErrorConstraintId() == 2).findFirst().orElseThrow();
        assertArrayEquals(new int[] { 1 }, mit.getInvolvedParameters());
        assertArrayEquals(new int[] { 2 }, mit.getMissingValues());
        assertInstanceOf(DiagnosisSets.class, mit.getExplanation());

        diagnosisSets = (DiagnosisSets) mit.getExplanation();
        assertEquals(3, diagnosisSets.getDiagnosisSets().size());

        diagnosisSet = diagnosisSets.getDiagnosisSets().get(0);
        assertEquals(1, diagnosisSet.getDiagnosisElements().size());
        assertTrue(diagnosisSet.getDiagnosisElements().stream().anyMatch(element ->
                element.getDiagnosedConstraintId() == 1
                        && Arrays.equals(new int[] { 0 }, element.getInvolvedParameters())
                        && Arrays.equals(new int[] { 2 }, element.getConflictingValues())));

        diagnosisSet = diagnosisSets.getDiagnosisSets().get(1);
        assertEquals(1, diagnosisSet.getDiagnosisElements().size());
        assertTrue(diagnosisSet.getDiagnosisElements().stream().anyMatch(element ->
                element.getDiagnosedConstraintId() == 4
                        && Arrays.equals(new int[] { 0, 1 }, element.getInvolvedParameters())
                        && Arrays.equals(new int[] { 0, 2 }, element.getConflictingValues())));

        diagnosisSet = diagnosisSets.getDiagnosisSets().get(2);
        assertEquals(1, diagnosisSet.getDiagnosisElements().size());
        assertTrue(diagnosisSet.getDiagnosisElements().stream().anyMatch(element ->
                element.getDiagnosedConstraintId() == 5
                        && Arrays.equals(new int[] { 0, 1 }, element.getInvolvedParameters())
                        && Arrays.equals(new int[] { 1, 2 }, element.getConflictingValues())));

        // getNegatedErrorConstraintId() == 4
        mit = mits.stream().filter(tuple -> tuple.getNegatedErrorConstraintId() == 4).findFirst().orElseThrow();
        assertArrayEquals(new int[] { 0, 1 }, mit.getInvolvedParameters());
        assertArrayEquals(new int[] { 0, 2 }, mit.getMissingValues());
        assertInstanceOf(InconsistentBackground.class, mit.getExplanation());

        // getNegatedErrorConstraintId() == 5
        mit = mits.stream().filter(tuple -> tuple.getNegatedErrorConstraintId() == 5).findFirst().orElseThrow();
        assertArrayEquals(new int[] { 0, 1 }, mit.getInvolvedParameters());
        assertArrayEquals(new int[] { 1, 2 }, mit.getMissingValues());
        assertInstanceOf(InconsistentBackground.class, mit.getExplanation());
    }

    @Test
    void testCTA2019ExampleWithInconsistentBackground() {
        final ConflictDetectionConfiguration configuration = new ConflictDetectionConfiguration(
                true,
                false,
                true,
                QuickConflictExplainer.class,
                true,
                ExhaustiveConflictDiagnostician.class);

        final List<TupleList> errorTupleLists = new ArrayList<>();
        errorTupleLists.add(new TupleList(1, new int[]{0}, Collections.singletonList(new int[]{2}), true));  // [Title:123]
        errorTupleLists.add(new TupleList(2, new int[]{1}, Collections.singletonList(new int[]{2})));                      // [GivenName:123]
        errorTupleLists.add(new TupleList(3, new int[]{2}, Collections.singletonList(new int[]{2})));                      // [FamilyName:123]
        errorTupleLists.add(new TupleList(4, new int[]{0, 1}, Arrays.asList(new int[]{0, 1}, new int[]{0, 2}), true));    // [Title:Mr,GivenName:Jane], [Title:Mr,GivenName:123]
        errorTupleLists.add(new TupleList(5, new int[]{0, 1}, Arrays.asList(new int[]{1, 0}, new int[]{1, 2}), true));    // [Title:Mrs,GivenName:John], [Title:Mrs,GivenName:123]

        final TestModel model = new TestModel(2, new int[]{3, 3, 3}, Collections.emptyList(), errorTupleLists);

        final ConflictDetectionManager manager = new ConflictDetectionManager(configuration, model);
        final List<MissingInvalidTuple> mits = manager.detectMissingInvalidTuples();

        assertEquals(3, mits.size());

        MissingInvalidTuple mit;
        DiagnosisSets diagnosisSets;
        DiagnosisSet diagnosisSet;

        // getNegatedErrorConstraintId() == 2
        mit = mits.stream().filter(tuple -> tuple.getNegatedErrorConstraintId() == 2).findFirst().orElseThrow();
        assertArrayEquals(new int[] { 1 }, mit.getInvolvedParameters());
        assertArrayEquals(new int[] { 2 }, mit.getMissingValues());
        assertInstanceOf(InconsistentBackground.class, mit.getExplanation());

        // getNegatedErrorConstraintId() == 4
        mit = mits.stream().filter(tuple -> tuple.getNegatedErrorConstraintId() == 4).findFirst().orElseThrow();
        assertArrayEquals(new int[] { 0, 1 }, mit.getInvolvedParameters());
        assertArrayEquals(new int[] { 0, 2 }, mit.getMissingValues());
        assertInstanceOf(DiagnosisSets.class, mit.getExplanation());

        diagnosisSets = (DiagnosisSets) mit.getExplanation();
        assertEquals(1, diagnosisSets.getDiagnosisSets().size());

        diagnosisSet = diagnosisSets.getDiagnosisSets().get(0);
        assertEquals(1, diagnosisSet.getDiagnosisElements().size());
        assertTrue(diagnosisSet.getDiagnosisElements().stream().anyMatch(element ->
                element.getDiagnosedConstraintId() == 2
                        && Arrays.equals(new int[] { 1 }, element.getInvolvedParameters())
                        && Arrays.equals(new int[] { 2 }, element.getConflictingValues())));

        // getNegatedErrorConstraintId() == 5
        mit = mits.stream().filter(tuple -> tuple.getNegatedErrorConstraintId() == 5).findFirst().orElseThrow();
        assertArrayEquals(new int[] { 0, 1 }, mit.getInvolvedParameters());
        assertArrayEquals(new int[] { 1, 2 }, mit.getMissingValues());
        assertInstanceOf(DiagnosisSets.class, mit.getExplanation());

        diagnosisSets = (DiagnosisSets) mit.getExplanation();
        assertEquals(1, diagnosisSets.getDiagnosisSets().size());

        diagnosisSet = diagnosisSets.getDiagnosisSets().get(0);
        assertEquals(1, diagnosisSet.getDiagnosisElements().size());
        assertTrue(diagnosisSet.getDiagnosisElements().stream().anyMatch(element ->
                element.getDiagnosedConstraintId() == 2
                        && Arrays.equals(new int[] { 1 }, element.getInvolvedParameters())
                        && Arrays.equals(new int[] { 2 }, element.getConflictingValues())));
    }

    @Test
    void testCTA2019ExampleWithDetectionExplanationAndDiagnosis() {
        final ConflictDetectionConfiguration configuration = new ConflictDetectionConfiguration(
                true,
                false,
                true,
                QuickConflictExplainer.class,
                true,
                ExhaustiveConflictDiagnostician.class);

        final List<TupleList> errorTupleLists = new ArrayList<>();
        errorTupleLists.add(new TupleList(1, new int[]{0}, Collections.singletonList(new int[]{2})));               // [Title:123]
        errorTupleLists.add(new TupleList(2, new int[]{1}, Collections.singletonList(new int[]{2})));               // [GivenName:123]
        errorTupleLists.add(new TupleList(3, new int[]{2}, Collections.singletonList(new int[]{2})));               // [FamilyName:123]
        errorTupleLists.add(new TupleList(4, new int[]{0, 1}, Arrays.asList(new int[]{0, 1}, new int[]{0, 2})));    // [Title:Mr,GivenName:Jane], [Title:Mr,GivenName:123]
        errorTupleLists.add(new TupleList(5, new int[]{0, 1}, Arrays.asList(new int[]{1, 0}, new int[]{1, 2})));    // [Title:Mrs,GivenName:John], [Title:Mrs,GivenName:123]

        final TestModel model = new TestModel(2, new int[]{3, 3, 3}, Collections.emptyList(), errorTupleLists);

        final ConflictDetectionManager manager = new ConflictDetectionManager(configuration, model);
        final List<MissingInvalidTuple> mits = manager.detectMissingInvalidTuples();

        assertEquals(3, mits.size());

        MissingInvalidTuple mit;
        DiagnosisSets diagnosisSets;
        DiagnosisSet diagnosisSet;

        // getNegatedErrorConstraintId() == 2
        mit = mits.stream().filter(tuple -> tuple.getNegatedErrorConstraintId() == 2).findFirst().orElseThrow();
        assertArrayEquals(new int[] { 1 }, mit.getInvolvedParameters());
        assertArrayEquals(new int[] { 2 }, mit.getMissingValues());
        assertInstanceOf(DiagnosisSets.class, mit.getExplanation());

        diagnosisSets = (DiagnosisSets) mit.getExplanation();
        assertEquals(3, diagnosisSets.getDiagnosisSets().size());

        diagnosisSet = diagnosisSets.getDiagnosisSets().get(0);
        assertEquals(1, diagnosisSet.getDiagnosisElements().size());
        assertTrue(diagnosisSet.getDiagnosisElements().stream().anyMatch(element ->
                element.getDiagnosedConstraintId() == 1
                        && Arrays.equals(new int[] { 0 }, element.getInvolvedParameters())
                        && Arrays.equals(new int[] { 2 }, element.getConflictingValues())));

        diagnosisSet = diagnosisSets.getDiagnosisSets().get(1);
        assertEquals(1, diagnosisSet.getDiagnosisElements().size());
        assertTrue(diagnosisSet.getDiagnosisElements().stream().anyMatch(element ->
                element.getDiagnosedConstraintId() == 4
                        && Arrays.equals(new int[] { 0, 1 }, element.getInvolvedParameters())
                        && Arrays.equals(new int[] { 0, 2 }, element.getConflictingValues())));

        diagnosisSet = diagnosisSets.getDiagnosisSets().get(2);
        assertEquals(1, diagnosisSet.getDiagnosisElements().size());
        assertTrue(diagnosisSet.getDiagnosisElements().stream().anyMatch(element ->
                element.getDiagnosedConstraintId() == 5
                        && Arrays.equals(new int[] { 0, 1 }, element.getInvolvedParameters())
                        && Arrays.equals(new int[] { 1, 2 }, element.getConflictingValues())));

        // getNegatedErrorConstraintId() == 4
        mit = mits.stream().filter(tuple -> tuple.getNegatedErrorConstraintId() == 4).findFirst().orElseThrow();
        assertArrayEquals(new int[] { 0, 1 }, mit.getInvolvedParameters());
        assertArrayEquals(new int[] { 0, 2 }, mit.getMissingValues());
        assertInstanceOf(DiagnosisSets.class, mit.getExplanation());

        diagnosisSets = (DiagnosisSets) mit.getExplanation();
        assertEquals(1, diagnosisSets.getDiagnosisSets().size());

        diagnosisSet = diagnosisSets.getDiagnosisSets().get(0);
        assertEquals(1, diagnosisSet.getDiagnosisElements().size());
        assertTrue(diagnosisSet.getDiagnosisElements().stream().anyMatch(element ->
                element.getDiagnosedConstraintId() == 2
                        && Arrays.equals(new int[] { 1 }, element.getInvolvedParameters())
                        && Arrays.equals(new int[] { 2 }, element.getConflictingValues())));

        // getNegatedErrorConstraintId() == 5
        mit = mits.stream().filter(tuple -> tuple.getNegatedErrorConstraintId() == 5).findFirst().orElseThrow();
        assertArrayEquals(new int[] { 0, 1 }, mit.getInvolvedParameters());
        assertArrayEquals(new int[] { 1, 2 }, mit.getMissingValues());
        assertInstanceOf(DiagnosisSets.class, mit.getExplanation());

        diagnosisSets = (DiagnosisSets) mit.getExplanation();
        assertEquals(1, diagnosisSets.getDiagnosisSets().size());

        diagnosisSet = diagnosisSets.getDiagnosisSets().get(0);
        assertEquals(1, diagnosisSet.getDiagnosisElements().size());
        assertTrue(diagnosisSet.getDiagnosisElements().stream().anyMatch(element ->
                element.getDiagnosedConstraintId() == 2
                        && Arrays.equals(new int[] { 1 }, element.getInvolvedParameters())
                        && Arrays.equals(new int[] { 2 }, element.getConflictingValues())));
    }

    @Test
    void testCTA2019ExampleWithDetectionExplanationButNoDiagnosis() {
        final ConflictDetectionConfiguration configuration = new ConflictDetectionConfiguration(
                true,
                false,
                true,
                QuickConflictExplainer.class,
                false,
                null);

        final List<TupleList> errorTupleLists = new ArrayList<>();
        errorTupleLists.add(new TupleList(1, new int[]{0}, Collections.singletonList(new int[]{2})));               // [Title:123]
        errorTupleLists.add(new TupleList(2, new int[]{1}, Collections.singletonList(new int[]{2})));               // [GivenName:123]
        errorTupleLists.add(new TupleList(3, new int[]{2}, Collections.singletonList(new int[]{2})));               // [FamilyName:123]
        errorTupleLists.add(new TupleList(4, new int[]{0, 1}, Arrays.asList(new int[]{0, 1}, new int[]{0, 2})));    // [Title:Mr,GivenName:Jane], [Title:Mr,GivenName:123]
        errorTupleLists.add(new TupleList(5, new int[]{0, 1}, Arrays.asList(new int[]{1, 0}, new int[]{1, 2})));    // [Title:Mrs,GivenName:John], [Title:Mrs,GivenName:123]

        final TestModel model = new TestModel(2, new int[]{3, 3, 3}, Collections.emptyList(), errorTupleLists);

        final ConflictDetectionManager manager = new ConflictDetectionManager(configuration, model);
        final List<MissingInvalidTuple> mits = manager.detectMissingInvalidTuples();

        assertEquals(3, mits.size());

        assertInstanceOf(ConflictSet.class, findMIT(mits, 2).getExplanation());
        assertArrayEquals(new int[] {2}, findMIT(mits, 2).getMissingValues());

        assertTrue(((ConflictSet) findMIT(mits, 2).getExplanation())
                        .getConflictElements()
                        .stream()
                        .anyMatch(conflict ->
                                conflict.getConflictingConstraintId() == 1
                                && Arrays.equals(new int[] {0}, conflict.getInvolvedParameters())
                                && Arrays.equals(new int[] {2}, conflict.getConflictingValues()))
        );
        assertTrue(((ConflictSet) findMIT(mits, 2).getExplanation())
                        .getConflictElements()
                        .stream()
                        .anyMatch(conflict ->
                                conflict.getConflictingConstraintId() == 4
                                        && Arrays.equals(new int[] {0, 1}, conflict.getInvolvedParameters())
                                        && Arrays.equals(new int[] {0, 2}, conflict.getConflictingValues()))
        );
        assertTrue(((ConflictSet) findMIT(mits, 2).getExplanation())
                        .getConflictElements()
                        .stream()
                        .anyMatch(conflict ->
                                conflict.getConflictingConstraintId() == 5
                                        && Arrays.equals(new int[] {0, 1}, conflict.getInvolvedParameters())
                                        && Arrays.equals(new int[] {1, 2}, conflict.getConflictingValues()))
        );
    }

    @Test
    void testCTA2019ExampleWithDetectionButNoExplanationAndNoDiagnosis() {
        final ConflictDetectionConfiguration configuration = new ConflictDetectionConfiguration(
                true,
                false,
                false,
                null,
                false,
                null);

        final List<TupleList> errorTupleLists = new ArrayList<>();
        errorTupleLists.add(new TupleList(1, new int[]{0}, Collections.singletonList(new int[]{2})));               // [Title:123]
        errorTupleLists.add(new TupleList(2, new int[]{1}, Collections.singletonList(new int[]{2})));               // [GivenName:123]
        errorTupleLists.add(new TupleList(3, new int[]{2}, Collections.singletonList(new int[]{2})));               // [FamilyName:123]
        errorTupleLists.add(new TupleList(4, new int[]{0, 1}, Arrays.asList(new int[]{0, 1}, new int[]{0, 2})));    // [Title:Mr,GivenName:Jane], [Title:Mr,GivenName:123]
        errorTupleLists.add(new TupleList(5, new int[]{0, 1}, Arrays.asList(new int[]{1, 0}, new int[]{1, 2})));    // [Title:Mrs,GivenName:John], [Title:Mrs,GivenName:123]

        final TestModel model = new TestModel(2, new int[]{3, 3, 3}, Collections.emptyList(), errorTupleLists);

        final ConflictDetectionManager manager = new ConflictDetectionManager(configuration, model);
        final List<MissingInvalidTuple> mits = manager.detectMissingInvalidTuples();

        assertEquals(3, mits.size());

        assertInstanceOf(UnknownConflictExplanation.class, findMIT(mits, 2).getExplanation());
        assertArrayEquals(new int[] {2}, findMIT(mits, 2).getMissingValues());

        assertInstanceOf(UnknownConflictExplanation.class, findMIT(mits, 4).getExplanation());
        assertArrayEquals(new int[] {0, 2}, findMIT(mits, 4).getMissingValues());

        assertInstanceOf(UnknownConflictExplanation.class, findMIT(mits, 5).getExplanation());
        assertArrayEquals(new int[] {1, 2}, findMIT(mits, 5).getMissingValues());
    }

    @Test
    void testCTA2019ExampleWithNoDetectionNoExplanationAndNoDiagnosis() {
        final ConflictDetectionConfiguration configuration = new ConflictDetectionConfiguration(
                false,
                false,
                false,
                null,
                false,
                null);

        final List<TupleList> errorTupleLists = new ArrayList<>();
        errorTupleLists.add(new TupleList(1, new int[]{0}, Collections.singletonList(new int[]{2})));               // [Title:123]
        errorTupleLists.add(new TupleList(2, new int[]{1}, Collections.singletonList(new int[]{2})));               // [GivenName:123]
        errorTupleLists.add(new TupleList(3, new int[]{2}, Collections.singletonList(new int[]{2})));               // [FamilyName:123]
        errorTupleLists.add(new TupleList(4, new int[]{0, 1}, Arrays.asList(new int[]{0, 1}, new int[]{0, 2})));    // [Title:Mr,GivenName:Jane], [Title:Mr,GivenName:123]
        errorTupleLists.add(new TupleList(5, new int[]{0, 1}, Arrays.asList(new int[]{1, 0}, new int[]{1, 2})));    // [Title:Mrs,GivenName:John], [Title:Mrs,GivenName:123]

        final TestModel model = new TestModel(2, new int[]{3, 3, 3}, Collections.emptyList(), errorTupleLists);

        final ConflictDetectionManager manager = new ConflictDetectionManager(configuration, model);
        final List<MissingInvalidTuple> conflicts = manager.detectMissingInvalidTuples();

        assertEquals(0, conflicts.size());
    }

    private MissingInvalidTuple findMIT(List<MissingInvalidTuple> mits,
                                        int negatedErrorConstraintId) {
        return mits.stream()
                .filter(tuple -> tuple.getNegatedErrorConstraintId() == negatedErrorConstraintId)
                .findFirst()
                .orElseThrow();
    }
}
