package de.rwth.swc.coffee4j.engine.constraint;

import de.rwth.swc.coffee4j.engine.TestModel;
import de.rwth.swc.coffee4j.engine.TupleList;
import de.rwth.swc.coffee4j.engine.conflict.InternalDiagnosisSets;
import de.rwth.swc.coffee4j.engine.conflict.InternalMissingInvalidTuple;
import org.junit.jupiter.api.Test;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

class InternalConflictDiagnosisManagerTest {

    @Test
    void testGetAllDiagnosesForExplicitConflict() {
        final List<TupleList> errorTupleLists = new ArrayList<>();
        errorTupleLists.add(new TupleList(1, new int[]{0}, Collections.singletonList(new int[]{2})));                       // [Title:123]
        errorTupleLists.add(new TupleList(2, new int[]{1}, Collections.singletonList(new int[]{2})));                       // [GivenName:123]
        errorTupleLists.add(new TupleList(3, new int[]{2}, Collections.singletonList(new int[]{2})));                       // [FamilyName:123]
        errorTupleLists.add(new TupleList(4, new int[]{0, 1}, Arrays.asList(new int[]{0, 1}, new int[]{0, 2})));            // [Title:Mr,GivenName:Jane], [Title:Mr,GivenName:123]
        errorTupleLists.add(new TupleList(5, new int[]{0, 1}, Arrays.asList(new int[]{1, 0}, new int[]{1, 2})));            // [Title:Mrs,GivenName:John], [Title:Mrs,GivenName:123]

        final TestModel testModel = new TestModel(2, new int[]{3, 3, 3}, Collections.emptyList(), errorTupleLists);

        final List<InternalMissingInvalidTuple> missingInvalidTuples
                = new InternalConflictDiagnosisManager().diagnose(testModel, errorTupleLists.get(4));

        assertEquals(1, missingInvalidTuples.size());
        assertEquals(5, missingInvalidTuples.get(0).getNegatedErrorConstraintId());
        assertEquals(1, ((InternalDiagnosisSets) missingInvalidTuples.get(0).getExplanation()).getDiagnosisSets().length);
        assertEquals(1, ((InternalDiagnosisSets) missingInvalidTuples.get(0).getExplanation()).getDiagnosisSets()[0].length);
        assertEquals(2, ((InternalDiagnosisSets) missingInvalidTuples.get(0).getExplanation()).getDiagnosisSets()[0][0]);
    }

    @Test
    void testGetAllDiagnosesForImplicitConflict() {
        final List<TupleList> errorTupleLists = new ArrayList<>();
        errorTupleLists.add(new TupleList(1, new int[]{0}, Collections.singletonList(new int[]{2})));                       // [Title:123]
        errorTupleLists.add(new TupleList(2, new int[]{1}, Collections.singletonList(new int[]{2})));                       // [GivenName:123]
        errorTupleLists.add(new TupleList(3, new int[]{2}, Collections.singletonList(new int[]{2})));                       // [FamilyName:123]
        errorTupleLists.add(new TupleList(4, new int[]{0, 1}, Arrays.asList(new int[]{0, 1}, new int[]{0, 2})));            // [Title:Mr,GivenName:Jane], [Title:Mr,GivenName:123]
        errorTupleLists.add(new TupleList(5, new int[]{0, 1}, Arrays.asList(new int[]{1, 0}, new int[]{1, 2})));            // [Title:Mrs,GivenName:John], [Title:Mrs,GivenName:123]

        final TestModel testModel = new TestModel(2, new int[]{3, 3, 3}, Collections.emptyList(), errorTupleLists);

        final List<InternalMissingInvalidTuple> missingInvalidTuples
                = new InternalConflictDiagnosisManager().diagnose(testModel, errorTupleLists.get(1));

        assertEquals(1, missingInvalidTuples.size());
        assertEquals(2, missingInvalidTuples.get(0).getNegatedErrorConstraintId());
        assertEquals(3, ((InternalDiagnosisSets) missingInvalidTuples.get(0).getExplanation()).getDiagnosisSets().length);
        assertEquals(1, ((InternalDiagnosisSets) missingInvalidTuples.get(0).getExplanation()).getDiagnosisSets()[0].length);
        assertEquals(1, ((InternalDiagnosisSets) missingInvalidTuples.get(0).getExplanation()).getDiagnosisSets()[1].length);
        assertEquals(1, ((InternalDiagnosisSets) missingInvalidTuples.get(0).getExplanation()).getDiagnosisSets()[2].length);
        assertEquals(1, ((InternalDiagnosisSets) missingInvalidTuples.get(0).getExplanation()).getDiagnosisSets()[0][0]);
        assertEquals(4, ((InternalDiagnosisSets) missingInvalidTuples.get(0).getExplanation()).getDiagnosisSets()[1][0]);
        assertEquals(5, ((InternalDiagnosisSets) missingInvalidTuples.get(0).getExplanation()).getDiagnosisSets()[2][0]);
    }

    @Test
    void testIgnoreCorrectnessOfConstraints() {
        final List<TupleList> errorTupleLists = new ArrayList<>();
        errorTupleLists.add(new TupleList(1, new int[]{0}, Collections.singletonList(new int[]{2}), true));   // [Title:123]
        errorTupleLists.add(new TupleList(2, new int[]{1}, Collections.singletonList(new int[]{2})));                       // [GivenName:123]
        errorTupleLists.add(new TupleList(3, new int[]{2}, Collections.singletonList(new int[]{2})));                       // [FamilyName:123]
        errorTupleLists.add(new TupleList(4, new int[]{0, 1}, Arrays.asList(new int[]{0, 1}, new int[]{0, 2})));            // [Title:Mr,GivenName:Jane], [Title:Mr,GivenName:123]
        errorTupleLists.add(new TupleList(5, new int[]{0, 1}, Arrays.asList(new int[]{1, 0}, new int[]{1, 2})));            // [Title:Mrs,GivenName:John], [Title:Mrs,GivenName:123]

        final TestModel testModel = new TestModel(2, new int[]{3, 3, 3}, Collections.emptyList(), errorTupleLists);

        final List<InternalMissingInvalidTuple> missingInvalidTuples
                = new InternalConflictDiagnosisManager().diagnose(testModel, errorTupleLists.get(1));

        assertEquals(1, missingInvalidTuples.size());
        assertEquals(2, missingInvalidTuples.get(0).getNegatedErrorConstraintId());
        assertEquals(3, ((InternalDiagnosisSets) missingInvalidTuples.get(0).getExplanation()).getDiagnosisSets().length);
        assertEquals(1, ((InternalDiagnosisSets) missingInvalidTuples.get(0).getExplanation()).getDiagnosisSets()[0].length);
        assertEquals(1, ((InternalDiagnosisSets) missingInvalidTuples.get(0).getExplanation()).getDiagnosisSets()[1].length);
        assertEquals(1, ((InternalDiagnosisSets) missingInvalidTuples.get(0).getExplanation()).getDiagnosisSets()[2].length);
        assertEquals(1, ((InternalDiagnosisSets) missingInvalidTuples.get(0).getExplanation()).getDiagnosisSets()[0][0]);
        assertEquals(4, ((InternalDiagnosisSets) missingInvalidTuples.get(0).getExplanation()).getDiagnosisSets()[1][0]);
        assertEquals(5, ((InternalDiagnosisSets) missingInvalidTuples.get(0).getExplanation()).getDiagnosisSets()[2][0]);
    }
}
