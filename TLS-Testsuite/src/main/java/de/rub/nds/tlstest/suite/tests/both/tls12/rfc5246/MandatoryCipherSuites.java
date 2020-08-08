package de.rub.nds.tlstest.suite.tests.both.tls12.rfc5246;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;


@RFC(number = 5246, section = "9")
public class MandatoryCipherSuites extends Tls12Test {

    @TlsTest(description = "A TLS-compliant application MUST implement the cipher suite TLS_RSA_WITH_AES_128_CBC_SHA", interoperabilitySeverity = SeverityLevel.MEDIUM)
    public void verify() {
        if (!context.getSiteReport().getCipherSuites().contains(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA)) {
            throw new AssertionError("Target does not support mandatory ciphersuite TLS_RSA_WITH_AES_128_CBC_SHA");
        }
    }

}
