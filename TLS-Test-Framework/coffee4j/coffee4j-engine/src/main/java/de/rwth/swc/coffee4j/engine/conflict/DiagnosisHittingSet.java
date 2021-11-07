package de.rwth.swc.coffee4j.engine.conflict;

import de.rwth.swc.coffee4j.engine.util.Preconditions;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

public class DiagnosisHittingSet {

    private final List<DiagnosisElement> diagnosisElements;

    public DiagnosisHittingSet(List<DiagnosisElement> diagnosisElements) {
        Preconditions.notNull(diagnosisElements);
        Preconditions.check(diagnosisElements.size() > 0);
        Preconditions.check(containsNoDuplicates(diagnosisElements));

        this.diagnosisElements = new ArrayList<>(diagnosisElements);

        Collections.sort(this.diagnosisElements);
    }

    private boolean containsNoDuplicates(List<DiagnosisElement> diagnosisElements) {
        for(int i = 0; i < diagnosisElements.size(); i++) {
            final DiagnosisElement currentElement = diagnosisElements.get(i);

            for(int j = 0; j < diagnosisElements.size(); j++) {
                final DiagnosisElement otherElement = diagnosisElements.get(j);

                if(i != j && currentElement.equals(otherElement)) {
                    return false;
                }
            }
        }

        return true;
    }

    public List<DiagnosisElement> getDiagnosisElements() {
        return diagnosisElements;
    }

    public boolean covers(DiagnosisHittingSet other) {
        Preconditions.notNull(other);

        return other.getDiagnosisElements().stream().allMatch(this::contains);
    }

    public boolean contains(DiagnosisElement otherElement) {
        Preconditions.notNull(otherElement);

        return diagnosisElements.stream()
                .anyMatch(diagnosisElement -> diagnosisElement.equals(otherElement));
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        DiagnosisHittingSet that = (DiagnosisHittingSet) o;
        return diagnosisElements.equals(that.diagnosisElements);
    }

    @Override
    public int hashCode() {
        return Objects.hash(diagnosisElements);
    }

    @Override
    public String toString() {
        return "DiagnosisHittingSet{" +
                "diagnosisElements=" + diagnosisElements +
                '}';
    }
}
