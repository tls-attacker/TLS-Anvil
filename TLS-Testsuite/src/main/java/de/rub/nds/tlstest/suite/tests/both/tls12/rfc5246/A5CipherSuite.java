/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.both.tls12.rfc5246;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

public class A5CipherSuite extends Tls12Test {

    @Test
    public void negotiateTLS_NULL_WITH_NULL_NULL() {
        List<CipherSuite> suites =
                new ArrayList<>(context.getFeatureExtractionResult().getCipherSuites());
        if (suites.contains(CipherSuite.TLS_NULL_WITH_NULL_NULL)) {
            throw new AssertionError("TLS_NULL_WITH_NULL_NULL ciphersuite is supported");
        }
    }

    /*@AnvilTest*/
    @Test
    public void anonCipherSuites() {
        List<CipherSuite> suites =
                new ArrayList<>(context.getFeatureExtractionResult().getCipherSuites());
        List<CipherSuite> forbidden = CipherSuite.getImplemented();
        forbidden.removeIf(i -> !i.toString().contains("_anon_"));

        List<String> errors = new ArrayList<>();
        for (CipherSuite i : forbidden) {
            if (suites.contains(i)) {
                errors.add(i.toString());
            }
        }

        if (errors.size() > 0) {
            throw new AssertionError(
                    String.format(
                            "The following ciphersuites should not be supported: %s",
                            String.join(", ", errors)));
        }
    }
}
