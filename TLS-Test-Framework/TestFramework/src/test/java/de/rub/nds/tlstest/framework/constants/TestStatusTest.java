package de.rub.nds.tlstest.framework.constants;

import org.junit.Test;

import static org.junit.Assert.*;

public class TestStatusTest {

    @Test
    public void partiallyFailed() {
        TestResult status = TestResult.resultForBitmask((TestResult.SUCCEEDED.getValue() | TestResult.FAILED.getValue() | TestResult.PARTIALLY_SUCCEEDED.getValue()));
        assertEquals(TestResult.PARTIALLY_FAILED, status);

        status = TestResult.resultForBitmask((TestResult.FAILED.getValue() | TestResult.PARTIALLY_SUCCEEDED.getValue()));
        assertEquals(TestResult.PARTIALLY_FAILED, status);

        status = TestResult.resultForBitmask((TestResult.FAILED.getValue() | TestResult.SUCCEEDED.getValue()));
        assertEquals(TestResult.PARTIALLY_FAILED, status);
    }

    @Test
    public void partiallySucceeded() {
        TestResult status = TestResult.resultForBitmask((TestResult.SUCCEEDED.getValue() | TestResult.PARTIALLY_SUCCEEDED.getValue()));
        assertEquals(TestResult.PARTIALLY_SUCCEEDED, status);
    }

    @Test(expected = UnsupportedOperationException.class)
    public void containsNotSpecified() {
        TestResult.resultForBitmask((TestResult.SUCCEEDED.getValue() | TestResult.NOT_SPECIFIED.getValue()));
    }

    @Test(expected = UnsupportedOperationException.class)
    public void containsDisabled() {
        TestResult.resultForBitmask((TestResult.SUCCEEDED.getValue() | TestResult.DISABLED.getValue()));
    }

    @Test()
    public void returnDefault() {
        TestResult status = TestResult.resultForBitmask(0);
        assertEquals(TestResult.NOT_SPECIFIED, status);
    }
}