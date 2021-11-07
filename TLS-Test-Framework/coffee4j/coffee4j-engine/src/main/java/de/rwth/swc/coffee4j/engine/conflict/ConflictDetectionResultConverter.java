package de.rwth.swc.coffee4j.engine.conflict;

import de.rwth.swc.coffee4j.engine.TestModel;
import de.rwth.swc.coffee4j.engine.TupleList;
import de.rwth.swc.coffee4j.engine.util.Preconditions;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

class ConflictDetectionResultConverter {

    private final TestModel testModel;
    private final TestModelExpander expander;

    ConflictDetectionResultConverter(TestModel testModel, TestModelExpander expander) {
        Preconditions.notNull(testModel);
        Preconditions.notNull(expander);

        this.testModel = testModel;
        this.expander = expander;
    }

    MissingInvalidTuple convertMissingInvalidTuple(InternalMissingInvalidTuple internal) {
        final int id = expander.computeOriginalId(internal.getNegatedErrorConstraintId());
        final int[] parameters = internal.getInvolvedParameters();
        final int[] values = internal.getMissingValues();
        final ConflictExplanation explanation = convertExplanation(internal.getExplanation());

        return new MissingInvalidTuple(id, parameters, values, explanation);
    }

    private ConflictExplanation convertExplanation(InternalExplanation explanation) {
        if(explanation instanceof InternalConflictSet) {
            return convertConflictSet((InternalConflictSet) explanation);
        } else if(explanation instanceof InternalInconsistentBackground) {
            return convertInconsistentBackground((InternalInconsistentBackground) explanation);
        } else if(explanation instanceof InternalUnknownExplanation) {
            return convertUnknownExplanation();
        } else if(explanation instanceof InternalDiagnosisSets) {
            return convertDiagnosisSets((InternalDiagnosisSets) explanation);
        } else {
            throw new IllegalStateException("unhandled ConflictExplanation subtype");
        }
    }

    ConflictSet convertConflictSet(InternalConflictSet conflict) {
        final List<ConflictElement> elements = Arrays.stream(conflict.getConflictSet())
                .mapToObj(this::convertConflictElement)
                .collect(Collectors.toList());

        return new ConflictSet(elements);
    }

    ConflictElement convertConflictElement(int constraintId) {
        final TupleList expandedTupleList = getExpandedTupleList(constraintId);

        return new ConflictElement(
                expander.computeOriginalId(constraintId),
                expandedTupleList.getInvolvedParameters(),
                expandedTupleList.getTuples().get(0));
    }

    InconsistentBackground convertInconsistentBackground(InternalInconsistentBackground inconsistentBackground) {
        final List<ConflictElement> elements = Arrays.stream(inconsistentBackground.getBackground())
                .mapToObj(this::convertConflictElement)
                .collect(Collectors.toList());

        return new InconsistentBackground(elements);
    }

    private UnknownConflictExplanation convertUnknownExplanation() {
        return new UnknownConflictExplanation();
    }

    DiagnosisSets convertDiagnosisSets(InternalDiagnosisSets diagnosis) {
        final ConflictSet conflictSet = convertConflictSet(diagnosis.getRootConflictSet());

        final List<DiagnosisSet> elements = Arrays.stream(diagnosis.getDiagnosisSets())
                .map(this::convertDiagnosisSet)
                .collect(Collectors.toList());

        return new DiagnosisSets(conflictSet, elements);
    }

    DiagnosisSet convertDiagnosisSet(int[] diagnosisSet) {
        final List<DiagnosisElement> elements = Arrays.stream(diagnosisSet)
                .mapToObj(this::convertDiagnosisElement)
                .collect(Collectors.toList());

        return new DiagnosisSet(elements);
    }

    DiagnosisElement convertDiagnosisElement(int constraintId) {
        final TupleList expandedTupleList = getExpandedTupleList(constraintId);

        return new DiagnosisElement(
                expander.computeOriginalId(constraintId),
                expandedTupleList.getInvolvedParameters(),
                expandedTupleList.getTuples().get(0));
    }

    private TupleList getExpandedTupleList(int id) {
        final Optional<TupleList> original = testModel.getForbiddenTupleLists().stream()
                .filter(tupleList -> tupleList.getId() == id)
                .findFirst();

        return original.or(
                () ->  testModel.getErrorTupleLists().stream()
                        .filter(tupleList -> tupleList.getId() == id)
                        .findFirst()
        ).orElseThrow();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ConflictDetectionResultConverter converter = (ConflictDetectionResultConverter) o;
        return testModel.equals(converter.testModel) &&
                expander.equals(converter.expander);
    }

    @Override
    public int hashCode() {
        return Objects.hash(testModel, expander);
    }

    @Override
    public String toString() {
        return "ConflictDetectionResultConverter{" +
                "testModel=" + testModel +
                ", expander=" + expander +
                '}';
    }
}
