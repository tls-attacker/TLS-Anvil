package de.rub.nds.tlstest.framework.annotations.methodCondition;

import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.api.extension.ExtensionContext;

class OtherClassCondition {

    public static OtherClassCondition instance;
    public boolean publicTest = false;
    public boolean privateTest = false;

    OtherClassCondition() {
        OtherClassCondition.instance = this;
    }

    public ConditionEvaluationResult publicTest(ExtensionContext context) {
        this.publicTest = true;
        return ConditionEvaluationResult.enabled("");
    }

    public ConditionEvaluationResult privateTest(ExtensionContext context) {
        this.privateTest = true;
        return ConditionEvaluationResult.enabled("");
    }
}
