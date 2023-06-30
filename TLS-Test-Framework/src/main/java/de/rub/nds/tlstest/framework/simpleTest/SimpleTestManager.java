/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * Copyright 2022 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.simpleTest;

/**
 * A workaround to finalize the AnnotatedStateContainer without
 * Coffee4j's post faultcharacterization callback.
 */
public class SimpleTestManager {
    private int remainingTests;
    
    private final String testMethod;
    
    private final String testClass;

    public SimpleTestManager(int remainingTests, String testMethod, String testClass) {
        this.remainingTests = remainingTests;
        this.testMethod = testMethod;
        this.testClass = testClass;
    }
    
    public synchronized void testCompleted() {
        remainingTests--;
    }
    
    public synchronized boolean allTestsFinished() {
        return remainingTests == 0;
    }

    public String getTestMethod() {
        return testMethod;
    }

    public String getTestClass() {
        return testClass;
    }
    
}
