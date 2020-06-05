package de.rub.nds.tlstest.framework.annotations.methodCondition;

import de.rub.nds.tlstest.framework.annotations.MethodCondition;
import de.rub.nds.tlstest.framework.junitExtensions.MethodConditionExtension;
import de.rub.nds.tlstest.framework.utils.ConditionTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.RegisterExtension;

import static org.junit.Assert.assertTrue;


@MethodCondition(method = "classCondition")
public class MethodConditionAnnotationClassDisabled {

    @RegisterExtension
    static ConditionTest ext = new ConditionTest(MethodConditionExtension.class);

    public ConditionEvaluationResult classCondition(ExtensionContext context) {
        return ConditionEvaluationResult.disabled("");
    }

    public ConditionEvaluationResult test2(ExtensionContext context) {
        return ConditionEvaluationResult.enabled("");
    }

    public ConditionEvaluationResult disableC(ExtensionContext context) {
        return ConditionEvaluationResult.disabled("disabled");
    }

    public ConditionEvaluationResult noParameter() {
        return ConditionEvaluationResult.enabled("");
    }


    @Test
    @MethodCondition(method="test2")
    public void not_execute_validMethod() { }

    @Test
    @MethodCondition(method="disableC")
    public void not_execute_validMethod_disabled() { }

    @Test
    @MethodCondition(method="noParameter")
    public void not_execute_noParameter() { }

}
