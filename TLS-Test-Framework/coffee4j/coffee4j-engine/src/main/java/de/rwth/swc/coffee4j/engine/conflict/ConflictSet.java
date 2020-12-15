package de.rwth.swc.coffee4j.engine.conflict;

import de.rwth.swc.coffee4j.engine.util.Preconditions;

import java.util.List;
import java.util.Objects;

public class ConflictSet implements ConflictExplanation {

    private final List<ConflictElement> conflictElements;

    public ConflictSet(List<ConflictElement> conflictElements) {
        Preconditions.notNull(conflictElements);
        Preconditions.check(conflictElements.size() > 0);

        this.conflictElements = conflictElements;
    }

    public List<ConflictElement> getConflictElements() {
        return conflictElements;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ConflictSet that = (ConflictSet) o;
        return conflictElements.equals(that.conflictElements);
    }

    @Override
    public int hashCode() {
        return Objects.hash(conflictElements);
    }

    @Override
    public String toString() {
        return "ConflictSet{" +
                "conflictElements=" + conflictElements +
                '}';
    }
}
