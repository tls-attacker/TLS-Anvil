/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.junitExtensions;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlstest.framework.FeatureExtractionResult;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.annotations.TlsVersion;
import java.lang.reflect.Method;
import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.api.extension.ExtensionContext;

/**
 * Evaluates the TlsVersion annotation. A test is disabled if the target does not support the
 * TlsVersion the test is written for.
 */
public class TlsVersionCondition extends BaseCondition {
    private static final Logger LOGGER = LogManager.getLogger();

    @Override
    public ConditionEvaluationResult evaluateExecutionCondition(ExtensionContext extensionContext) {
        if (!extensionContext.getTestMethod().isPresent()) {
            return ConditionEvaluationResult.enabled("Class annotations are not relevant");
        }

        Method testMethod = extensionContext.getRequiredTestMethod();
        Class<?> testClass = extensionContext.getRequiredTestClass();

        TestContext context = TestContext.getInstance();
        FeatureExtractionResult report = context.getFeatureExtractionResult();
        Set<ProtocolVersion> protocolVersionList = report.getSupportedVersions();
        ProtocolVersion[] testSupportedVersions = getSupportedTestVersions(testMethod, testClass);

        if (testSupportedVersions.length == 0) {
            LOGGER.error(
                    "No TlsVersion annotation available. Use Tls12Test or Tls13Test class as superclass for your test class or annotate the test method/class with the TlsVersion annotation.");
            return ConditionEvaluationResult.disabled("No TlsVersion annotation present");
        } else if (versionsMatch(protocolVersionList, testSupportedVersions)) {
            return ConditionEvaluationResult.enabled(
                    "ProtocolVersion of the test is supported by the target");
        }

        return ConditionEvaluationResult.disabled(
                "ProtocolVersion of the test is not supported by the target");
    }

    public static boolean versionsMatch(
            Set<ProtocolVersion> supportedVersions, ProtocolVersion[] testVersions) {
        for (ProtocolVersion supportedVersion : testVersions) {
            if (supportedVersions.contains(supportedVersion)) {
                return true;
            }
        }
        return false;
    }

    public static ProtocolVersion[] getSupportedTestVersions(
            Method testMethod, Class<?> testClass) {
        if (testMethod.isAnnotationPresent(TlsVersion.class)) {
            return testMethod.getAnnotation(TlsVersion.class).supported();
        } else if (testClass.isAnnotationPresent(TlsVersion.class)) {
            return testClass.getAnnotation(TlsVersion.class).supported();
        } else {
            return new ProtocolVersion[0];
        }
    }
}
