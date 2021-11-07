package de.rwth.swc.coffee4j.engine.util;

import org.junit.jupiter.api.Test;

import static de.rwth.swc.coffee4j.engine.util.TupleUtil.tuplesAreEqual;
import static org.junit.jupiter.api.Assertions.*;

class TupleUtilTest {

    @Test
    void testEmptyEqual() {
        assertTrue(tuplesAreEqual(
                new int[] {}, new int[] {},
                new int[] {}, new int[] {}));
    }

    @Test
    void testSingleEqual() {
        assertTrue(tuplesAreEqual(
                new int[] {0}, new int[] {0},
                new int[] {0}, new int[] {0}));
    }

    @Test
    void testSingleEqualParameterOnly() {
        assertFalse(tuplesAreEqual(
                new int[] {0}, new int[] {0},
                new int[] {0}, new int[] {1}));
    }

    @Test
    void testSingleEqualValueOnly() {
        assertFalse(tuplesAreEqual(
                new int[] {0}, new int[] {0},
                new int[] {1}, new int[] {0}));
    }

    @Test
    void testEqualParametersAndValues() {
        assertTrue(tuplesAreEqual(
                new int[] {0, 1}, new int[] {0, 0},
                new int[] {0, 1}, new int[] {0, 0}));
    }

    @Test
    void testEqualParametersOnly() {
        assertFalse(tuplesAreEqual(
                new int[] {0, 1}, new int[] { 0, 0},
                new int[] {0, 1}, new int[] { 1, 0}));
    }

    @Test
    void testEqualValuesOnly() {
        assertFalse(tuplesAreEqual(
                new int[] {0, 1}, new int[] {0, 0},
                new int[] {0, 2}, new int[] {0, 0}));
    }

    @Test
    void testEqualsWithDifferentOrdering() {
        assertTrue(tuplesAreEqual(
                new int[] {0, 1}, new int[] {0, 1},
                new int[] {1, 0}, new int[] {1, 0}));
    }

    @Test
    void testNotEqualsWithDifferentOrdering() {
        assertFalse(tuplesAreEqual(
                new int[] {0, 1}, new int[] {1, 0},
                new int[] {1, 0}, new int[] {1, 0}));
    }

    @Test
    void testParametersNull() {
        assertThrows(NullPointerException.class, () -> tuplesAreEqual(
                null, new int[] {0},
                new int[] {0}, new int[] {0}));
    }

    @Test
    void testValuesNull() {
        assertThrows(NullPointerException.class, () -> tuplesAreEqual(
                new int[] {0}, null,
                new int[] {0}, new int[] {0}));
    }

    @Test
    void testOtherParametersNull() {
        assertThrows(NullPointerException.class, () -> tuplesAreEqual(
                new int[] {0}, new int[] {0},
                null, new int[] {0}));
    }

    @Test
    void testOtherValuesNull() {
        assertThrows(NullPointerException.class, () -> tuplesAreEqual(
                new int[] {0}, new int[] {0},
                new int[] {0}, null));
    }

    @Test
    void testTooManyValues() {
        assertThrows(IllegalArgumentException.class, () -> tuplesAreEqual(
                new int[] {0}, new int[] {0, 1},
                new int[] {0}, new int[] {0}));
    }

    @Test
    void testTooFewValues() {
        assertThrows(IllegalArgumentException.class, () -> tuplesAreEqual(
                new int[] {0, 1}, new int[] {0},
                new int[] {0}, new int[] {0}));
    }

    @Test
    void testTooManyOtherValues() {
        assertThrows(IllegalArgumentException.class, () -> tuplesAreEqual(
                new int[] {0}, new int[] {0},
                new int[] {0}, new int[] {0, 1}));
    }

    @Test
    void testTooFewOtherValues() {
        assertThrows(IllegalArgumentException.class, () -> tuplesAreEqual(
                new int[] {0}, new int[] {0},
                new int[] {0, 1}, new int[] {0}));
    }

    @Test
    void testDifferentTupleSizes() {
        assertDoesNotThrow(() -> tuplesAreEqual(
                new int[] {0}, new int[] {0},
                new int[] {0, 1}, new int[] {0, 1}));
    }

    @Test
    void testDuplicateParameters() {
        assertThrows(IllegalArgumentException.class, () -> tuplesAreEqual(
                new int[] {0, 0}, new int[] {0, 0},
                new int[] {0, 1}, new int[] {0, 0}));
    }

    @Test
    void testDuplicateOtherParameters() {
        assertThrows(IllegalArgumentException.class, () -> tuplesAreEqual(
                new int[] {0, 1}, new int[] {0, 0},
                new int[] {0, 0}, new int[] {0, 0}));
    }
}
