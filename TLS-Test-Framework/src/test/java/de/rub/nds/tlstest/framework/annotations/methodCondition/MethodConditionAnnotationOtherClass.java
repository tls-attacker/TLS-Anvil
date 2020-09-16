/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.annotations.methodCondition;

import de.rub.nds.tlstest.framework.annotations.MethodCondition;
import de.rub.nds.tlstest.framework.junitExtensions.MethodConditionExtension;
import de.rub.nds.tlstest.framework.utils.ConditionTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import static org.junit.Assert.assertTrue;


public class MethodConditionAnnotationOtherClass {

    @RegisterExtension
    static ConditionTest ext = new ConditionTest(MethodConditionExtension.class);

    @Test
    @MethodCondition(clazz = OtherClassCondition.class, method="publicTest")
    public void execute_validPublicMethod() {
        assertTrue(OtherClassCondition.instance.publicTest);
    }

    @Test
    @MethodCondition(clazz = OtherClassCondition.class, method="privateTest")
    public void execute_validPrivateMethod() {
        assertTrue(OtherClassCondition.instance.privateTest);
    }

    @Test
    public void execute_noAnnotation() { }

}
