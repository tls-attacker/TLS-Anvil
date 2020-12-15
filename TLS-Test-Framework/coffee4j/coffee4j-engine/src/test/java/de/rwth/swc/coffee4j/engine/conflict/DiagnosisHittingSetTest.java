package de.rwth.swc.coffee4j.engine.conflict;

import org.junit.jupiter.api.Test;

import static java.util.Arrays.asList;
import static java.util.Collections.singletonList;
import static org.junit.jupiter.api.Assertions.*;

class DiagnosisHittingSetTest {

    @Test
    void testOrderedListOfDiagnosisElements() {
        final DiagnosisHittingSet a = new DiagnosisHittingSet(asList(
                new DiagnosisElement(1, new int[] {0}, new int[]{2}),
                new DiagnosisElement(5, new int[] {0, 1}, new int[]{1, 2}),
                new DiagnosisElement(4, new int[] {0, 1}, new int[]{0, 2})));

        assertEquals(1, a.getDiagnosisElements().get(0).getDiagnosedConstraintId());
        assertEquals(4, a.getDiagnosisElements().get(1).getDiagnosedConstraintId());
        assertEquals(5, a.getDiagnosisElements().get(2).getDiagnosedConstraintId());
    }

    @Test
    void testEqualsWithElementsInSameOrder() {
        final DiagnosisHittingSet a = new DiagnosisHittingSet(asList(
                new DiagnosisElement(1, new int[] {0}, new int[]{2}),
                new DiagnosisElement(4, new int[] {0, 1}, new int[]{0, 2}),
                new DiagnosisElement(5, new int[] {0, 1}, new int[]{1, 2})));

        final DiagnosisHittingSet b = new DiagnosisHittingSet(asList(
                new DiagnosisElement(1, new int[] {0}, new int[]{2}),
                new DiagnosisElement(4, new int[] {0, 1}, new int[]{0, 2}),
                new DiagnosisElement(5, new int[] {0, 1}, new int[]{1, 2})));

        assertEquals(a, b);
        assertEquals(b, a);
    }

    @Test
    void testEqualsWithElementsInDifferentOrder() {
        final DiagnosisHittingSet a = new DiagnosisHittingSet(asList(
                new DiagnosisElement(1, new int[] {0}, new int[]{2}),
                new DiagnosisElement(4, new int[] {0, 1}, new int[]{0, 2}),
                new DiagnosisElement(5, new int[] {0, 1}, new int[]{1, 2})));

        final DiagnosisHittingSet b = new DiagnosisHittingSet(asList(
                new DiagnosisElement(4, new int[] {0, 1}, new int[]{0, 2}),
                new DiagnosisElement(1, new int[] {0}, new int[]{2}),
                new DiagnosisElement(5, new int[] {0, 1}, new int[]{1, 2})));

        assertEquals(a, b);
        assertEquals(b, a);
    }

    @Test
    void testNoDuplicateDiagnosisElements() {
        assertDoesNotThrow(() -> new DiagnosisHittingSet(asList(
                    new DiagnosisElement(1, new int[] {0}, new int[]{2}),
                    new DiagnosisElement(4, new int[] {0, 1}, new int[]{0, 2}),
                    new DiagnosisElement(5, new int[] {0, 1}, new int[]{1, 2})))
        );

        assertDoesNotThrow(() -> new DiagnosisHittingSet(asList(
                new DiagnosisElement(1, new int[] {0}, new int[]{2}),
                new DiagnosisElement(4, new int[] {0, 1}, new int[]{0, 2}),
                new DiagnosisElement(4, new int[] {0, 1}, new int[]{1, 2})))
        );
    }

    @Test
    void testDuplicateDiagnosisElements() {
        assertThrows(IllegalArgumentException.class, () -> new DiagnosisHittingSet(asList(
                new DiagnosisElement(1, new int[] {0}, new int[]{2}),
                new DiagnosisElement(4, new int[] {0, 1}, new int[]{0, 2}),
                new DiagnosisElement(5, new int[] {0, 1}, new int[]{1, 2}),
                new DiagnosisElement(4, new int[] {0, 1}, new int[]{0, 2})))
        );
    }

    @Test
    void testCoversEqual() {
        final DiagnosisHittingSet a = new DiagnosisHittingSet(singletonList(
                new DiagnosisElement(1, new int[] {1}, new int[] {1})));
        final DiagnosisHittingSet b = new DiagnosisHittingSet(singletonList(
                new DiagnosisElement(1, new int[] {1}, new int[] {1})));

        assertTrue(a.covers(b));
        assertTrue(b.covers(a));
    }

    @Test
    void testCoversEqualElement() {
        final DiagnosisHittingSet a = new DiagnosisHittingSet(asList(
                new DiagnosisElement(1, new int[] {1}, new int[] {1}),
                new DiagnosisElement(2, new int[] {2}, new int[] {2})));
        final DiagnosisHittingSet b = new DiagnosisHittingSet(singletonList(
                new DiagnosisElement(1, new int[] {1}, new int[] {1})));

        assertTrue(a.covers(b));
        assertFalse(b.covers(a));
    }

    @Test
    void testDoesNotCover() {
        final DiagnosisHittingSet a = new DiagnosisHittingSet(asList(
                new DiagnosisElement(1, new int[] {1}, new int[] {1}),
                new DiagnosisElement(2, new int[] {0, 2}, new int[] {0, 1})));
        final DiagnosisHittingSet b = new DiagnosisHittingSet(singletonList(
                new DiagnosisElement(2, new int[] {0, 2}, new int[] {0, 2})));

        assertFalse(a.covers(b));
        assertFalse(b.covers(a));
    }

    @Test
    void testContains() {
        final DiagnosisHittingSet a = new DiagnosisHittingSet(asList(
                new DiagnosisElement(1, new int[] {1}, new int[] {1}),
                new DiagnosisElement(2, new int[] {0, 1}, new int[] {0, 1})));

        assertTrue(a.contains(new DiagnosisElement(1, new int[] {1}, new int[] {1})));
        assertTrue(a.contains(new DiagnosisElement(2, new int[] {0, 1}, new int[] {0, 1})));
        assertFalse(a.contains(new DiagnosisElement(1, new int[] {0, 1}, new int[] {0, 1})));
        assertFalse(a.contains(new DiagnosisElement(2, new int[] {1, 1}, new int[] {0, 1})));
        assertFalse(a.contains(new DiagnosisElement(2, new int[] {0, 1}, new int[] {1, 1})));
    }
}
