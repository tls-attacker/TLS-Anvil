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
import de.rub.nds.tlstest.framework.annotations.ValueConstraints;
import de.rub.nds.tlstest.framework.coffee4j.model.ModelFromScope;
import de.rub.nds.tlstest.framework.model.DerivationScope;
import de.rub.nds.tlstest.framework.model.DerivationType;
import de.rub.nds.tlstest.framework.model.constraint.ValueConstraint;
import de.rub.nds.tlstest.framework.model.derivationParameter.DerivationFactory;
import de.rub.nds.tlstest.framework.model.derivationParameter.DerivationParameter;
import java.lang.reflect.Method;
import java.util.LinkedList;
import java.util.List;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.api.extension.ExtensionContext;

/**
 *
 * @author marcel
 */
public class ValueConstraintsConditionExtension extends BaseCondition {
    @Override
    public ConditionEvaluationResult evaluateExecutionCondition(ExtensionContext extensionContext) {
        if (!extensionContext.getTestMethod().isPresent()) {
            return ConditionEvaluationResult.enabled("Class annotations are not relevant.");
        }
        
        DerivationScope derivationScope = new DerivationScope(extensionContext);
        for(ValueConstraint valContraint : derivationScope.getValueConstraints()) {
            DerivationParameter derivationParam = DerivationFactory.getInstance(valContraint.getAffectedType());
            if(derivationParam.getConstrainedParameterValues(TestContext.getInstance(), derivationScope).size() == 0) {
                return ConditionEvaluationResult.disabled("Host does not support required value for parameter " + derivationParam.getType());
            }
        }
        return ConditionEvaluationResult.enabled("");
    }
}
