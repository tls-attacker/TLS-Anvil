package de.rub.nds.tlstest.framework.annotations.tlsVersion;

import de.rub.nds.anvilcore.testhelper.ConditionTest;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlstest.framework.ServerFeatureExtractionResult;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.junitExtensions.TlsVersionCondition;
import java.util.HashSet;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.extension.RegisterExtension;

public class TlsVersionTest {
    @RegisterExtension static ConditionTest ext = new ConditionTest(TlsVersionCondition.class);

    @BeforeAll
    static void setup() {
        TestContext testContext = TestContext.getInstance();
        ServerFeatureExtractionResult extractionResult =
                new ServerFeatureExtractionResult("", 4433);

        extractionResult.setSupportedVersions(
                new HashSet<ProtocolVersion>() {
                    {
                        add(ProtocolVersion.TLS12);
                        add(ProtocolVersion.SSL3);
                    }
                });

        testContext.setFeatureExtractionResult(extractionResult);
    }
}
