package de.rwth.swc.coffee4j.engine.conflict;

import de.rwth.swc.coffee4j.engine.util.Preconditions;

import java.util.Arrays;
import java.util.Objects;

public class ConflictElement {
    private final int conflictingConstraintId;
    private final int[] involvedParameters;
    private final int[] conflictingValues;

    public ConflictElement(int conflictingConstraintId,
                           int[] involvedParameters,
                           int[] conflictingValues) {
        Preconditions.check(conflictingConstraintId > 0);
        Preconditions.notNull(involvedParameters);
        Preconditions.notNull(conflictingValues);

        this.conflictingConstraintId = conflictingConstraintId;
        this.involvedParameters = involvedParameters;
        this.conflictingValues = conflictingValues;
    }

    public int getConflictingConstraintId() {
        return conflictingConstraintId;
    }

    public int[] getConflictingValues() {
        return conflictingValues;
    }

    public int[] getInvolvedParameters() {
        return involvedParameters;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ConflictElement that = (ConflictElement) o;
        return conflictingConstraintId == that.conflictingConstraintId &&
                Arrays.equals(conflictingValues, that.conflictingValues) &&
                Arrays.equals(involvedParameters, that.involvedParameters);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(conflictingConstraintId);
        result = 31 * result + Arrays.hashCode(conflictingValues);
        result = 31 * result + Arrays.hashCode(involvedParameters);
        return result;
    }

    @Override
    public String toString() {
        return "ConflictElement{" +
                "conflictingConstraintId=" + conflictingConstraintId +
                ", conflictingValues=" + Arrays.toString(conflictingValues) +
                ", involvedParameters=" + Arrays.toString(involvedParameters) +
                '}';
    }
}
