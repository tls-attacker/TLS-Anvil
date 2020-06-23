package de.rub.nds.tlstest.framework.junitExtensions;

import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.constants.TestStatus;
import de.rub.nds.tlstest.framework.execution.AnnotatedStateContainer;
import de.rub.nds.tlstest.framework.utils.TestMethodConfig;
import org.junit.jupiter.api.extension.ExtensionContext;

import java.util.ArrayList;
import java.util.Optional;

public class TestWatcher implements org.junit.jupiter.api.extension.TestWatcher {

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
        createResult(context, TestStatus.SUCCEEDED);
    }

    @Override
    public void testFailed(ExtensionContext context, Throwable cause) {
        AnnotatedStateContainer result = createResult(context, TestStatus.FAILED);
        if (result != null) {
            result.setFailedStacktrace(cause);
        }
    }

    @Override
    public void testDisabled(ExtensionContext context, Optional<String> reason) {
        AnnotatedStateContainer result = createResult(context, TestStatus.DISABLED);
        if (result != null) {
            result.setDisabledReason(reason.orElse("No reason"));
        }
    }
}
