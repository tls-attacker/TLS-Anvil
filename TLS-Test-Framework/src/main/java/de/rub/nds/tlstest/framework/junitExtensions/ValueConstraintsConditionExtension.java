/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.junitExtensions;

import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.model.LegacyDerivationScope;
import de.rub.nds.tlstest.framework.model.TlsParameterType;
import de.rub.nds.tlstest.framework.model.constraint.ValueConstraint;
import de.rub.nds.tlstest.framework.model.derivationParameter.DerivationFactory;
import de.rub.nds.tlstest.framework.model.derivationParameter.DerivationParameter;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.api.extension.ExtensionContext;

public class ValueConstraintsConditionExtension extends BaseCondition {
    @Override
    public ConditionEvaluationResult evaluateExecutionCondition(ExtensionContext extensionContext) {
        if (!extensionContext.getTestMethod().isPresent()) {
            return ConditionEvaluationResult.enabled("Class annotations are not relevant.");
        }

        LegacyDerivationScope derivationScope = new LegacyDerivationScope(extensionContext);
        for (ValueConstraint valContraint : derivationScope.getValueConstraints()) {
            DerivationParameter derivationParam =
                    DerivationFactory.getInstance(valContraint.getAffectedType());
            if (derivationParam.hasNoApplicableValues(TestContext.getInstance(), derivationScope)) {
                return ConditionEvaluationResult.disabled(
                        "Host does not support required value for parameter "
                                + derivationParam.getType());
            }
        }

        for (TlsParameterType explicitType : derivationScope.getExplicitTypeValues().keySet()) {
            DerivationParameter derivationParam = DerivationFactory.getInstance(explicitType);
            if (derivationParam.hasNoApplicableValues(TestContext.getInstance(), derivationScope)) {
                return ConditionEvaluationResult.disabled(
                        "Host does not support required value for parameter " + explicitType);
            }
        }
        return ConditionEvaluationResult.enabled("");
    }
}
