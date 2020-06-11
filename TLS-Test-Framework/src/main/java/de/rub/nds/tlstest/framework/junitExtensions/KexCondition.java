package de.rub.nds.tlstest.framework.junitExtensions;

import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.constants.KeyX;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.api.extension.ExtensionContext;


public class KexCondition extends BaseCondition {
    private static final Logger LOGGER = LogManager.getLogger();


    @Override
    public ConditionEvaluationResult evaluateExecutionCondition(ExtensionContext extensionContext) {
        if (!extensionContext.getTestMethod().isPresent()) {
            return ConditionEvaluationResult.enabled("Class annotations are not relevant.");
        }

        KeyExchange resolvedKeyExchange = KeyX.resolveKexAnnotation(extensionContext);

        if (resolvedKeyExchange.supported().length > 0) {
            return ConditionEvaluationResult.enabled("Target supports Ciphersuites that are supported by the test.");
        }
        else {
            return ConditionEvaluationResult.disabled("Target does not provide Ciphersuites that are supported by the test.");
        }

    }
}
