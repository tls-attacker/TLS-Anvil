/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.constants;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import de.rub.nds.anvilcore.teststate.TestResult;
import org.junit.jupiter.api.Test;

public class TestStatusTest {

    @Test
    public void partiallyFailed() {
        TestResult status =
                TestResult.resultForBitmask(
                        (TestResult.STRICTLY_SUCCEEDED.getValue()
                                | TestResult.FULLY_FAILED.getValue()
                                | TestResult.CONCEPTUALLY_SUCCEEDED.getValue()));
        assertEquals(TestResult.PARTIALLY_FAILED, status);

        status =
                TestResult.resultForBitmask(
                        (TestResult.FULLY_FAILED.getValue()
                                | TestResult.CONCEPTUALLY_SUCCEEDED.getValue()));
        assertEquals(TestResult.PARTIALLY_FAILED, status);

        status =
                TestResult.resultForBitmask(
                        (TestResult.FULLY_FAILED.getValue()
                                | TestResult.STRICTLY_SUCCEEDED.getValue()));
        assertEquals(TestResult.PARTIALLY_FAILED, status);
    }

    @Test
    public void partiallySucceeded() {
        TestResult status =
                TestResult.resultForBitmask(
                        (TestResult.STRICTLY_SUCCEEDED.getValue()
                                | TestResult.CONCEPTUALLY_SUCCEEDED.getValue()));
        assertEquals(TestResult.CONCEPTUALLY_SUCCEEDED, status);
    }

    @Test()
    public void containsNotSpecified() {
        assertThrows(
                UnsupportedOperationException.class,
                () ->
                        TestResult.resultForBitmask(
                                (TestResult.STRICTLY_SUCCEEDED.getValue()
                                        | TestResult.NOT_SPECIFIED.getValue())));
    }

    @Test()
    public void containsDisabled() {
        assertThrows(
                UnsupportedOperationException.class,
                () ->
                        TestResult.resultForBitmask(
                                (TestResult.STRICTLY_SUCCEEDED.getValue()
                                        | TestResult.DISABLED.getValue())));
    }

    @Test()
    public void returnDefault() {
        TestResult status = TestResult.resultForBitmask(0);
        assertEquals(TestResult.NOT_SPECIFIED, status);
    }
}
