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
import de.rub.nds.tlstest.framework.constants.TestStatus;
import de.rub.nds.tlstest.framework.execution.AnnotatedStateContainer;
import de.rub.nds.tlstest.framework.utils.TestMethodConfig;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.extension.ExtensionContext;

import java.io.ByteArrayOutputStream;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Optional;

/**
 * The class contains methods that are called when a test case terminates.
 * If no AnnotatedStateContainer is associated with the finished test case
 * a new container is created.
 */
public class TestWatcher implements org.junit.jupiter.api.extension.TestWatcher {
    private static final Logger LOGGER = LogManager.getLogger();

    private AnnotatedStateContainer createResult(ExtensionContext context, TestStatus status) {
        TestContext.getInstance().testFinished();

        if (!context.getTestMethod().isPresent()) {
            return null;
        }

        String uniqueId = context.getUniqueId();
        if (TestContext.getInstance().getTestResults().get(uniqueId) != null) {
            return null;
        }

        TestMethodConfig testMethodConfig = new TestMethodConfig(context);
        AnnotatedStateContainer result = new AnnotatedStateContainer(uniqueId, testMethodConfig, new ArrayList<>());
        result.setStatus(status);

        TestContext.getInstance().addTestResult(result);
        return result;
    }


    @Override
    public void testSuccessful(ExtensionContext context) {
        TestContext.getInstance().testSucceeded();
        createResult(context, TestStatus.SUCCEEDED);
    }

    @Override
    public void testFailed(ExtensionContext context, Throwable cause) {
        TestContext.getInstance().testFailed();
        AnnotatedStateContainer result = createResult(context, TestStatus.FAILED);
        if (result != null) {
            result.setFailedStacktrace(cause);
        }

        if (!(cause instanceof AssertionError)) {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            PrintWriter writer = new PrintWriter(baos, true);
            cause.printStackTrace(writer);
            String content = new String(baos.toByteArray(), StandardCharsets.UTF_8);
            LOGGER.error(String.format("Test failed without AssertionError %s\n%s", context.getDisplayName(), content));
        }
    }

    @Override
    public void testDisabled(ExtensionContext context, Optional<String> reason) {
        TestContext.getInstance().testDisabled();
        AnnotatedStateContainer result = createResult(context, TestStatus.DISABLED);
        if (result != null) {
            result.setDisabledReason(reason.orElse("No reason"));
        }
    }
}
