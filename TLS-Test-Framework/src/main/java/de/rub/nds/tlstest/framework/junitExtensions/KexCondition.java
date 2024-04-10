/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.junitExtensions;

import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.constants.KeyX;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.api.extension.ExtensionContext;

/**
 * Evaluates the KeyExchange annotation and disables a test if the target does not support cipher
 * suites that the KeyExchange annotation requires.
 */
public class KexCondition extends BaseCondition {
    private static final Logger LOGGER = LogManager.getLogger();

    @Override
    public ConditionEvaluationResult evaluateExecutionCondition(ExtensionContext extensionContext) {
        if (!extensionContext.getTestMethod().isPresent()) {
            return ConditionEvaluationResult.enabled("Class annotations are not relevant.");
        }

        KeyExchange resolvedKeyExchange = KeyX.resolveKexAnnotation(extensionContext);

        if (resolvedKeyExchange.supported().length > 0) {
            return ConditionEvaluationResult.enabled(
                    "Target supports Ciphersuites that are supported by the test.");
        } else {
            return ConditionEvaluationResult.disabled(
                    "Target does not provide Ciphersuites that are supported by the test.");
        }
    }
}
