/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.junitExtensions;

import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.constraint.ValueConstraint;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.model.parameter.ParameterIdentifier;
import de.rub.nds.tlstest.framework.model.TlsParameterType;
import de.rub.nds.tlstest.framework.model.derivationParameter.DerivationFactory;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.api.extension.ExtensionContext;

public class ValueConstraintsConditionExtension extends BaseCondition {
    @Override
    public ConditionEvaluationResult evaluateExecutionCondition(ExtensionContext extensionContext) {
        if (!extensionContext.getTestMethod().isPresent()) {
            return ConditionEvaluationResult.enabled("Class annotations are not relevant.");
        }

        DerivationScope derivationScope = new DerivationScope(extensionContext);
        for (ValueConstraint valContraint : derivationScope.getValueConstraints()) {
            DerivationParameter derivationParam =
                    DerivationFactory.getInstance(
                            (TlsParameterType)
                                    valContraint.getAffectedParameter().getParameterType());
            if (derivationParam.hasNoApplicableValues(derivationScope)) {
                return ConditionEvaluationResult.disabled(
                        "Host does not support required value for parameter "
                                + derivationParam.getParameterIdentifier().name());
            }
        }

        for (ParameterIdentifier explicitType : derivationScope.getExplicitValues().keySet()) {
            DerivationParameter derivationParam =
                    DerivationFactory.getInstance(
                            (TlsParameterType) explicitType.getParameterType());
            if (derivationParam.hasNoApplicableValues(derivationScope)) {
                return ConditionEvaluationResult.disabled(
                        "Host does not support required value for parameter " + explicitType);
            }
        }
        return ConditionEvaluationResult.enabled("");
    }
}
