/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.annotations.keyExchange;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlstest.framework.ServerFeatureExtractionResult;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import java.util.HashSet;
import org.junit.jupiter.api.BeforeAll;

public class KexAnnotationTLS13 extends KexAnnotationTest {

    @BeforeAll
    static void setup() {
        TestContext testContext = TestContext.getInstance();
        ServerFeatureExtractionResult report = new ServerFeatureExtractionResult("", 4433);

        report.setSupportedCipherSuites(
                new HashSet<CipherSuite>() {
                    {
                        add(CipherSuite.TLS_AES_128_GCM_SHA256);
                    }
                });

        testContext.setFeatureExtractionResult(report);
    }

    @AnvilTest
    @KeyExchange(supported = KeyExchangeType.ALL13)
    public void execute_supported() {}

    @AnvilTest
    @KeyExchange(supported = KeyExchangeType.ALL12)
    public void not_execute_unsupported() {}
}
