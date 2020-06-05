package de.rub.nds.tlstest.framework.junitExtensions;

import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.constants.TestStatus;
import de.rub.nds.tlstest.framework.execution.AnnotatedStateContainer;
import de.rub.nds.tlstest.framework.utils.TestMethodConfig;
import org.junit.jupiter.api.extension.ExtensionContext;

import java.util.Optional;

public class TestWatcher implements org.junit.jupiter.api.extension.TestWatcher {

    @Override
    public void testFailed(ExtensionContext context, Throwable cause) {
        if (!context.getTestMethod().isPresent()) {
            return;
        }

        String uniqueId = context.getUniqueId();
        if (TestContext.getInstance().getTestResults().get(uniqueId) != null) {
            return;
        }

        TestMethodConfig testMethodConfig = new TestMethodConfig(context);
        AnnotatedStateContainer result = new AnnotatedStateContainer();
        result.setUniqueId(uniqueId);
        result.setStatus(TestStatus.FAILED);
        result.setFailedStacktrace(cause);
        result.setTestMethodConfig(testMethodConfig);

        TestContext.getInstance().addTestResult(result);
    }

    @Override
    public void testDisabled(ExtensionContext context, Optional<String> reason) {
        if (!context.getTestMethod().isPresent()) return;

        String uid = context.getUniqueId();
        AnnotatedStateContainer result = new AnnotatedStateContainer();
        result.setStatus(TestStatus.DISABLED);
        result.setDisabledReason(reason.orElse("No reason"));
        result.setUniqueId(uid);
        TestContext.getInstance().addTestResult(result);
    }
}
