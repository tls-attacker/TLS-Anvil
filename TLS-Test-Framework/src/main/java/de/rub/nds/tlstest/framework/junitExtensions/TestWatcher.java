/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.junitExtensions;

import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.constants.TestResult;
import de.rub.nds.tlstest.framework.execution.AnnotatedStateContainer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.extension.ExtensionContext;

import java.util.ArrayList;
import java.util.Optional;

/**
 * The class contains methods that are called when a test case terminates.
 * If no AnnotatedStateContainer is associated with the finished test case
 * a new container is created.
 */
public class TestWatcher implements org.junit.jupiter.api.extension.TestWatcher {
    private static final Logger LOGGER = LogManager.getLogger();

    private AnnotatedStateContainer createResult(ExtensionContext context, TestResult result) {
        TestContext.getInstance().testFinished();

        if (!context.getTestMethod().isPresent()) {
            return null;
        }

        String uniqueId = context.getUniqueId();
        if (TestContext.getInstance().getTestResults().get(uniqueId) != null) {
            return null;
        }

        AnnotatedStateContainer container = new AnnotatedStateContainer(context, new ArrayList<>());
        container.setResultRaw(result.getValue());

        TestContext.getInstance().addTestResult(container);
        return container;
    }


    @Override
    public void testSuccessful(ExtensionContext context) {
        TestContext.getInstance().testSucceeded();
        createResult(context, TestResult.SUCCEEDED);
    }

    @Override
    public void testFailed(ExtensionContext context, Throwable cause) {
        TestContext.getInstance().testFailed();
        AnnotatedStateContainer container = createResult(context, TestResult.FAILED);
        if (container != null) {
            container.setFailedStacktrace(cause);
        }

        if (!(cause instanceof AssertionError)) {
            LOGGER.error("Test failed without AssertionError {}\n", context.getDisplayName(), cause);
        }
    }

    @Override
    public void testDisabled(ExtensionContext context, Optional<String> reason) {
        TestContext.getInstance().testDisabled();
        AnnotatedStateContainer container = createResult(context, TestResult.DISABLED);
        if (container != null) {
            container.setDisabledReason(reason.orElse("No reason"));
        }
    }
}
