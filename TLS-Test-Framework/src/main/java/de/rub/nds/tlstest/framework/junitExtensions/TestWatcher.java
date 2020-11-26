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
import de.rub.nds.tlstest.framework.execution.AnnotatedState;
import de.rub.nds.tlstest.framework.execution.AnnotatedStateContainer;
import de.rub.nds.tlstest.framework.utils.ExecptionPrinter;
import de.rub.nds.tlstest.framework.utils.Utils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.extension.ExtensionContext;

import java.util.Optional;

/**
 * The class contains methods that are called when a test case terminates.
 * If no AnnotatedStateContainer is associated with the finished test case
 * a new container is created.
 */
public class TestWatcher implements org.junit.jupiter.api.extension.TestWatcher {
    private static final Logger LOGGER = LogManager.getLogger();

    private AnnotatedStateContainer createResult(ExtensionContext context, TestResult result) {

        String uniqueId = Utils.getTemplateContainerExtensionContext(context).getUniqueId();
        AnnotatedStateContainer container = TestContext.getInstance().getTestResults().get(uniqueId);
        if (container != null) {
            return container;
        }

        TestContext.getInstance().testFinished();
        container = AnnotatedStateContainer.forExtensionContext(context);
        container.setResultRaw(result.getValue());
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
        AnnotatedState state = container.getStates().stream()
                .filter(i -> i.getExtensionContext().getUniqueId().equals(context.getUniqueId()))
                .findFirst()
                .orElse(null);
        if (state == null) {
            if (Utils.extensionContextIsTemplateContainer(context.getParent().get())) {
                state = new AnnotatedState(context, null, null);
                state.setFailedReason(cause);
            } else {
                container.setFailedReason(ExecptionPrinter.stacktraceToString(cause));
            }
        }

        if (!(cause instanceof AssertionError)) {
            LOGGER.error("Test failed without AssertionError {}\n", context.getDisplayName(), cause);
        }
    }

    @Override
    public void testDisabled(ExtensionContext context, Optional<String> reason) {
        TestContext.getInstance().testDisabled();
        AnnotatedStateContainer container = createResult(context, TestResult.DISABLED);
        container.setDisabledReason(reason.orElse("No reason"));
    }
}
