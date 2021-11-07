package de.rwth.swc.coffee4j.engine.conflict;

import de.rwth.swc.coffee4j.engine.util.Preconditions;

import java.util.List;
import java.util.Objects;

public class DiagnosisSet {
    private final List<DiagnosisElement> diagnosisElements;

    public DiagnosisSet(List<DiagnosisElement> diagnosisElements) {
        Preconditions.notNull(diagnosisElements);
        Preconditions.check(diagnosisElements.size() > 0);

        this.diagnosisElements = diagnosisElements;
    }

    public List<DiagnosisElement> getDiagnosisElements() {
        return diagnosisElements;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        DiagnosisSet that = (DiagnosisSet) o;
        return diagnosisElements.equals(that.diagnosisElements);
    }

    @Override
    public int hashCode() {
        return Objects.hash(diagnosisElements);
    }

    @Override
    public String toString() {
        return "DiagnosisSet{" +
                "diagnosisElements=" + diagnosisElements +
                '}';
    }
}
