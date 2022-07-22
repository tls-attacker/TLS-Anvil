/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * Copyright 2022 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.constants;

import org.junit.Test;

import static org.junit.Assert.*;

public class TestStatusTest {

    @Test
    public void partiallyFailed() {
        TestResult status = TestResult.resultForBitmask((TestResult.STRICTLY_SUCCEEDED.getValue() | TestResult.FULLY_FAILED.getValue() | TestResult.CONCEPTUALLY_SUCCEEDED.getValue()));
        assertEquals(TestResult.PARTIALLY_FAILED, status);

        status = TestResult.resultForBitmask((TestResult.FULLY_FAILED.getValue() | TestResult.CONCEPTUALLY_SUCCEEDED.getValue()));
        assertEquals(TestResult.PARTIALLY_FAILED, status);

        status = TestResult.resultForBitmask((TestResult.FULLY_FAILED.getValue() | TestResult.STRICTLY_SUCCEEDED.getValue()));
        assertEquals(TestResult.PARTIALLY_FAILED, status);
    }

    @Test
    public void partiallySucceeded() {
        TestResult status = TestResult.resultForBitmask((TestResult.STRICTLY_SUCCEEDED.getValue() | TestResult.CONCEPTUALLY_SUCCEEDED.getValue()));
        assertEquals(TestResult.CONCEPTUALLY_SUCCEEDED, status);
    }

    @Test(expected = UnsupportedOperationException.class)
    public void containsNotSpecified() {
        TestResult.resultForBitmask((TestResult.STRICTLY_SUCCEEDED.getValue() | TestResult.NOT_SPECIFIED.getValue()));
    }

    @Test(expected = UnsupportedOperationException.class)
    public void containsDisabled() {
        TestResult.resultForBitmask((TestResult.STRICTLY_SUCCEEDED.getValue() | TestResult.DISABLED.getValue()));
    }

    @Test()
    public void returnDefault() {
        TestResult status = TestResult.resultForBitmask(0);
        assertEquals(TestResult.NOT_SPECIFIED, status);
    }
}