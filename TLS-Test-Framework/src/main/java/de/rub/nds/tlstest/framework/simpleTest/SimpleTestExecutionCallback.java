/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.simpleTest;

import de.rub.nds.tlstest.framework.execution.AnnotatedStateContainer;
import org.junit.jupiter.api.extension.AfterTestExecutionCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

/** */
public class SimpleTestExecutionCallback implements AfterTestExecutionCallback {

    public SimpleTestExecutionCallback() {}

    @Override
    public void afterTestExecution(ExtensionContext extensionContext) throws Exception {
        SimpleTestManager testManager =
                SimpleTestManagerContainer.getInstance().getManagerByExtension(extensionContext);
        testManager.testCompleted();
        if (testManager.allTestsFinished()) {
            AnnotatedStateContainer.forExtensionContext(extensionContext).finished();
        }
    }
}
