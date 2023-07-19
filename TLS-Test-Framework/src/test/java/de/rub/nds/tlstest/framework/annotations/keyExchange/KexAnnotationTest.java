package de.rub.nds.tlstest.framework.annotations.keyExchange;

import de.rub.nds.anvilcore.testhelper.ConditionTest;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlstest.framework.ServerFeatureExtractionResult;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.junitExtensions.KexCondition;
import java.util.HashSet;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.extension.RegisterExtension;

public abstract class KexAnnotationTest {

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
}
