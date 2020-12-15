package de.rwth.swc.coffee4j.engine.conflict;

import de.rwth.swc.coffee4j.engine.util.Preconditions;

import java.util.Arrays;
import java.util.Objects;

public class DiagnosisElement implements Comparable<DiagnosisElement> {
    private final int diagnosedConstraintId;
    private final int[] involvedParameters;
    private final int[] conflictingValues;

    public DiagnosisElement(int diagnosedConstraintId,
                            int[] involvedParameters,
                            int[] conflictingValues) {
        Preconditions.check(diagnosedConstraintId > 0);
        Preconditions.notNull(involvedParameters);
        Preconditions.check(involvedParameters.length > 0);
        Preconditions.notNull(conflictingValues);
        Preconditions.check(conflictingValues.length > 0);

        this.diagnosedConstraintId = diagnosedConstraintId;
        this.involvedParameters = involvedParameters;
        this.conflictingValues = conflictingValues;
    }

    public int getDiagnosedConstraintId() {
        return diagnosedConstraintId;
    }

    public int[] getInvolvedParameters() {
        return involvedParameters;
    }

    public int[] getConflictingValues() {
        return conflictingValues;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        DiagnosisElement that = (DiagnosisElement) o;
        return diagnosedConstraintId == that.diagnosedConstraintId &&
                Arrays.equals(involvedParameters, that.involvedParameters) &&
                Arrays.equals(conflictingValues, that.conflictingValues);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(diagnosedConstraintId);
        result = 31 * result + Arrays.hashCode(involvedParameters);
        result = 31 * result + Arrays.hashCode(conflictingValues);
        return result;
    }

    @Override
    public String toString() {
        return "DiagnosisElement{" +
                "diagnosedConstraintId=" + diagnosedConstraintId +
                ", involvedParameters=" + Arrays.toString(involvedParameters) +
                ", conflictingValues=" + Arrays.toString(conflictingValues) +
                '}';
    }

    @Override
    public int compareTo(DiagnosisElement other) {
        int compare = Integer.compare(this.getDiagnosedConstraintId(), other.getDiagnosedConstraintId());

        if (compare == 0) {
            compare = Arrays.compare(this.getInvolvedParameters(), other.getInvolvedParameters());

            if(compare == 0) {
                compare = Arrays.compare(this.getConflictingValues(), other.getConflictingValues());
            }
        }

        return compare;
    }
}
