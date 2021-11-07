package de.rwth.swc.coffee4j.engine.conflict;

import de.rwth.swc.coffee4j.engine.util.Preconditions;

import java.util.Arrays;
import java.util.Objects;

public class InternalDiagnosisSets implements InternalExplanation {
    private final InternalConflictSet rootConflictSet;
    private final int[][] diagnosisSets;

    public InternalDiagnosisSets(InternalConflictSet rootConflictSet, int[][] diagnosisSets) {
        Preconditions.notNull(rootConflictSet);
        Preconditions.notNull(diagnosisSets);

        this.rootConflictSet = rootConflictSet;
        this.diagnosisSets = diagnosisSets;
    }

    public InternalConflictSet getRootConflictSet() {
        return rootConflictSet;
    }

    public int[][] getDiagnosisSets() {
        return diagnosisSets;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        InternalDiagnosisSets that = (InternalDiagnosisSets) o;
        return rootConflictSet.equals(that.rootConflictSet) &&
                Arrays.equals(diagnosisSets, that.diagnosisSets);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(rootConflictSet);
        result = 31 * result + Arrays.hashCode(diagnosisSets);
        return result;
    }

    @Override
    public String toString() {
        return "InternalDiagnosisSets{" +
                "rootConflictSet=" + rootConflictSet +
                ", diagnosisSets=" + Arrays.toString(diagnosisSets) +
                '}';
    }
}
