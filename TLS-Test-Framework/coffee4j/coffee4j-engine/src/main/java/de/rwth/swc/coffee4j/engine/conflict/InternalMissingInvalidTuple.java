package de.rwth.swc.coffee4j.engine.conflict;

import de.rwth.swc.coffee4j.engine.util.Preconditions;

import java.util.Arrays;
import java.util.Objects;

public class InternalMissingInvalidTuple {
    private final int negatedErrorConstraintId;
    private final int[] involvedParameters;
    private final int[] missingValues;
    private final InternalExplanation explanation;

    public InternalMissingInvalidTuple(int negatedErrorConstraintId,
                                       int[] involvedParameters,
                                       int[] missingValues,
                                       InternalExplanation explanation) {
        Preconditions.check(negatedErrorConstraintId > 0);
        Preconditions.notNull(involvedParameters);
        Preconditions.notNull(missingValues);
        Preconditions.notNull(explanation);

        this.negatedErrorConstraintId = negatedErrorConstraintId;
        this.involvedParameters = involvedParameters;
        this.missingValues = missingValues;
        this.explanation = explanation;
    }

    public int getNegatedErrorConstraintId() {
        return negatedErrorConstraintId;
    }

    public int[] getInvolvedParameters() {
        return involvedParameters;
    }

    public int[] getMissingValues() {
        return missingValues;
    }

    public InternalExplanation getExplanation() {
        return explanation;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        InternalMissingInvalidTuple that = (InternalMissingInvalidTuple) o;
        return negatedErrorConstraintId == that.negatedErrorConstraintId &&
                Arrays.equals(involvedParameters, that.involvedParameters) &&
                Arrays.equals(missingValues, that.missingValues) &&
                explanation.equals(that.explanation);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(negatedErrorConstraintId, explanation);
        result = 31 * result + Arrays.hashCode(involvedParameters);
        result = 31 * result + Arrays.hashCode(missingValues);
        return result;
    }

    @Override
    public String toString() {
        return "InternalMissingInvalidTuple{" +
                "negatedErrorConstraintId=" + negatedErrorConstraintId +
                ", involvedParameters=" + Arrays.toString(involvedParameters) +
                ", missingValues=" + Arrays.toString(missingValues) +
                ", explanation=" + explanation +
                '}';
    }
}
