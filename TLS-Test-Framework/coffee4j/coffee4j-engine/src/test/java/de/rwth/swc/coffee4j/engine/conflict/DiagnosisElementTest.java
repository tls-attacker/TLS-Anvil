package de.rwth.swc.coffee4j.engine.conflict;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class DiagnosisElementTest {

    @Test
    void testCompareToWithDifferentDiagnosedConstraintIds() {
        final DiagnosisElement a = new DiagnosisElement(4, new int[] {0, 1}, new int[]{0, 2});
        final DiagnosisElement b = new DiagnosisElement(1, new int[] {0}, new int[]{2});

        assertEquals(1, a.compareTo(b));
        assertEquals(-1, b.compareTo(a));
    }

    @Test
    void testCompareToWithDifferentConflictingValues() {
        final DiagnosisElement a = new DiagnosisElement(4, new int[] {0, 1}, new int[]{0, 2});
        final DiagnosisElement b = new DiagnosisElement(4, new int[] {0, 1}, new int[]{1, 2});

        assertEquals(-1, a.compareTo(b));
        assertEquals(1, b.compareTo(a));
    }

    @Test
    void testCompareToWithEqualElements() {
        final DiagnosisElement a = new DiagnosisElement(4, new int[] {0, 1}, new int[]{0, 2});
        final DiagnosisElement b = new DiagnosisElement(4, new int[] {0, 1}, new int[]{0, 2});

        assertEquals(0, a.compareTo(b));
        assertEquals(0, b.compareTo(a));
    }
}
