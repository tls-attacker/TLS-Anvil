package de.rub.nds.tlstest.framework.constants;

import org.junit.Test;

import static org.junit.Assert.*;

public class TestStatusTest {

    @Test
    public void partiallyFailed() {
        TestStatus status = TestStatus.statusForBitmask((TestStatus.SUCCEEDED.getValue() | TestStatus.FAILED.getValue() | TestStatus.PARTIALLY_SUCCEEDED.getValue()));
        assertEquals(TestStatus.PARTIALLY_FAILED, status);

        status = TestStatus.statusForBitmask((TestStatus.FAILED.getValue() | TestStatus.PARTIALLY_SUCCEEDED.getValue()));
        assertEquals(TestStatus.PARTIALLY_FAILED, status);

        status = TestStatus.statusForBitmask((TestStatus.FAILED.getValue() | TestStatus.SUCCEEDED.getValue()));
        assertEquals(TestStatus.PARTIALLY_FAILED, status);
    }

    @Test
    public void partiallySucceeded() {
        TestStatus status = TestStatus.statusForBitmask((TestStatus.SUCCEEDED.getValue() | TestStatus.PARTIALLY_SUCCEEDED.getValue()));
        assertEquals(TestStatus.PARTIALLY_SUCCEEDED, status);
    }

    @Test(expected = UnsupportedOperationException.class)
    public void containsNotSpecified() {
        TestStatus.statusForBitmask((TestStatus.SUCCEEDED.getValue() | TestStatus.NOT_SPECIFIED.getValue()));
    }

    @Test(expected = UnsupportedOperationException.class)
    public void containsDisabled() {
        TestStatus.statusForBitmask((TestStatus.SUCCEEDED.getValue() | TestStatus.DISABLED.getValue()));
    }

    @Test()
    public void returnDefault() {
        TestStatus status = TestStatus.statusForBitmask(0);
        assertEquals(TestStatus.NOT_SPECIFIED, status);
    }
}