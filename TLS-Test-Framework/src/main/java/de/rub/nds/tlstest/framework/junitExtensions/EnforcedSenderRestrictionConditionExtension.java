/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlstest.framework.junitExtensions;

import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.annotations.EnforcedSenderRestriction;
import java.lang.reflect.Method;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.api.extension.ExtensionContext;

public class EnforcedSenderRestrictionConditionExtension extends BaseCondition {
    @Override
    public ConditionEvaluationResult evaluateExecutionCondition(ExtensionContext extensionContext) {
        if (!extensionContext.getTestMethod().isPresent()) {
            return ConditionEvaluationResult.enabled("Class annotations are not relevant.");
        }

        Method testMethod = extensionContext.getRequiredTestMethod();
        Class<?> testClass = extensionContext.getRequiredTestClass();

        if ((testMethod.isAnnotationPresent(EnforcedSenderRestriction.class)
                        || testClass.isAnnotationPresent(EnforcedSenderRestriction.class))
                && !TestContext.getInstance().getConfig().isEnforceSenderRestrictions()) {
            return ConditionEvaluationResult.disabled(
                    "Sender restrictions are not expected to be enforced");
        }

        return ConditionEvaluationResult.enabled("Sender restrictions are expected to be enforced");
    }
}
