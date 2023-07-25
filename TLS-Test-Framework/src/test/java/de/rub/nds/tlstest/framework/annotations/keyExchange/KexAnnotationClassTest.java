/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.annotations.keyExchange;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.testhelper.ConditionTest;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlstest.framework.ServerFeatureExtractionResult;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.junitExtensions.KexCondition;
import java.util.HashSet;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.extension.RegisterExtension;

@KeyExchange(supported = KeyExchangeType.ECDH)
public class KexAnnotationClassTest {

    @RegisterExtension static ConditionTest ext = new ConditionTest(KexCondition.class);

    @BeforeAll
    static void setup() {
        TestContext testContext = TestContext.getInstance();
        ServerFeatureExtractionResult report = new ServerFeatureExtractionResult("", 4433);

        report.setSupportedCipherSuites(
                new HashSet<CipherSuite>() {
                    {
                        add(CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA);
                    }
                });

        testContext.setFeatureExtractionResult(report);
    }

    @AnvilTest
    public void execute_inheritedClassAnnoation() {}

    @AnvilTest
    @KeyExchange(
            supported = {},
            mergeSupportedWithClassSupported = true)
    public void execute_mergedWithClassAnnoation() {}

    @AnvilTest
    @KeyExchange(supported = KeyExchangeType.DH)
    public void not_execute_unsupportedKex() {}
}
