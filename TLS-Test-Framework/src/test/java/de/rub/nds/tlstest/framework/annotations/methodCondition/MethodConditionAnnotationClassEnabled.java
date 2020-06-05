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
public class MethodConditionAnnotationClassEnabled {

    @RegisterExtension
    static ConditionTest ext = new ConditionTest(MethodConditionExtension.class);

    private boolean methodConditionExecuted = false;
    private boolean classConditionExecuted = false;

    public ConditionEvaluationResult classCondition(ExtensionContext context) {
        classConditionExecuted = true;
        return ConditionEvaluationResult.enabled("");
    }

    public ConditionEvaluationResult test2(ExtensionContext context) {
        methodConditionExecuted = true;
        return ConditionEvaluationResult.enabled("");
    }

    private ConditionEvaluationResult privateEnabled(ExtensionContext context) {
        methodConditionExecuted = true;
        return ConditionEvaluationResult.enabled("");
    }

    public ConditionEvaluationResult disableC(ExtensionContext context) {
        methodConditionExecuted = true;
        return ConditionEvaluationResult.disabled("disabled");
    }

    static private ConditionEvaluationResult staticPrivateEnabled(ExtensionContext context) {
        return ConditionEvaluationResult.enabled("");
    }

    static public ConditionEvaluationResult staticPublicEnabled(ExtensionContext context) {
        return ConditionEvaluationResult.enabled("");
    }

    public ConditionEvaluationResult noParameter() {
        return ConditionEvaluationResult.enabled("");
    }


    @Test
    @MethodCondition(method="test2")
    public void execute_validMethod() {
        assertTrue("Class ConditionMethod executed", classConditionExecuted);
        assertTrue("Method ConditionMethod executed", methodConditionExecuted);
    }

    @Test
    @MethodCondition(method="staticPrivateEnabled")
    public void execute_staticPrivateEnabled() { }

    @Test
    @MethodCondition(method="staticPublicEnabled")
    public void execute_staticPublicEnabled() { }

    @Test
    @MethodCondition(method="privateEnabled")
    public void execute_PrivateEnabled() {
        assertTrue("Class ConditionMethod executed", classConditionExecuted);
        assertTrue("Method ConditionMethod executed", methodConditionExecuted);
    }

    @Test
    @MethodCondition(method="noParameter")
    public void execute_noParameter() { }

    @Test
    @MethodCondition(method="disableC")
    public void not_execute_validMethod_disabled() { }

}
