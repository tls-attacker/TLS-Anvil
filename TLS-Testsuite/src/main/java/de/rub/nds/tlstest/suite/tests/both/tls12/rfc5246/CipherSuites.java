/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.both.tls12.rfc5246;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.anvilcore.annotation.NonCombinatorialAnvilTest;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

public class CipherSuites extends Tls12Test {

    @NonCombinatorialAnvilTest(id = "5246-jxPrq1MPSR")
    public void supportOfDeprecatedCipherSuites() {
        List<CipherSuite> suites =
                new LinkedList<>(context.getFeatureExtractionResult().getCipherSuites());

        List<String> badSuites = new ArrayList<>();
        for (CipherSuite i : suites) {
            if (AlgorithmResolver.getCipher(i).toString().contains("IDEA")) {
                badSuites.add(i.toString());
            } else if (AlgorithmResolver.getCipher(i).toString().contains("_DES")) {
                badSuites.add(i.toString());
            } else if (AlgorithmResolver.getCipher(i).toString().contains("RC4")) {
                badSuites.add(i.toString());
            }
        }

        assertEquals(
                0,
                badSuites.size(),
                "Deprecated Ciphersuites supported: " + String.join(", ", badSuites));
    }
}
