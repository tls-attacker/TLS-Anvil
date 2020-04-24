package de.rub.nds.tlstest.framework.annotations.methodCondition;

import de.rub.nds.tlstest.framework.annotations.MethodCondition;
import de.rub.nds.tlstest.framework.junitExtensions.MethodConditionExtension;
import de.rub.nds.tlstest.framework.utils.ConditionTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.RegisterExtension;


@MethodCondition(method = "aspfok3")
public class MethodConditionAnnotationClassInvalid {

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


    @Test
    @MethodCondition(method="test2")
    public void not_execute_validMethod() { }

    @Test
    @MethodCondition(method="disableC")
    public void not_execute_validMethod_disabled() { }

    @Test
    @MethodCondition(method="asfoij3e")
    public void not_execute_invalidMethod() { }
}
