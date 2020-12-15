package de.rwth.swc.coffee4j.engine.conflict;

import de.rwth.swc.coffee4j.engine.util.Preconditions;

import java.util.List;
import java.util.Objects;

public class DiagnosisSets implements ConflictExplanation {

    private final ConflictSet rootConflictSet;
    private final List<DiagnosisSet> diagnosisSets;

    DiagnosisSets(ConflictSet rootConflictSet,
                  List<DiagnosisSet> diagnosisSets) {
        Preconditions.notNull(rootConflictSet);
        Preconditions.notNull(diagnosisSets);
        Preconditions.check(diagnosisSets.size() > 0);

        this.rootConflictSet = rootConflictSet;
        this.diagnosisSets = diagnosisSets;
    }

    public ConflictSet getRootConflictSet() {
        return rootConflictSet;
    }

    public List<DiagnosisSet> getDiagnosisSets() {
        return diagnosisSets;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        DiagnosisSets that = (DiagnosisSets) o;
        return rootConflictSet.equals(that.rootConflictSet) &&
                diagnosisSets.equals(that.diagnosisSets);
    }

    @Override
    public int hashCode() {
        return Objects.hash(rootConflictSet, diagnosisSets);
    }

    @Override
    public String toString() {
        return "DiagnosisSets{" +
                "rootConflictSet=" + rootConflictSet +
                ", diagnosisSets=" + diagnosisSets +
                '}';
    }
}
