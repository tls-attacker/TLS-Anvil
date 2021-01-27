/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.both.tls12.rfc5246;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.TestDescription;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.annotations.categories.ComplianceCategory;
import de.rub.nds.tlstest.framework.annotations.categories.InteroperabilityCategory;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import org.junit.jupiter.api.Test;


@RFC(number = 5246, section = "9")
public class MandatoryCipherSuites extends Tls12Test {

    //@TlsTest(description = "A TLS-compliant application MUST implement the cipher suite TLS_RSA_WITH_AES_128_CBC_SHA")
    @Test
    @TestDescription("TLS_RSA_WITH_AES_128_CBC_SHA must be supported by all TLS 1.2 implementations")
    @InteroperabilityCategory(SeverityLevel.LOW)
    @ComplianceCategory(SeverityLevel.MEDIUM)
    public void verify() {
        if (!context.getSiteReport().getCipherSuites().contains(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA)) {
            throw new AssertionError("Target does not support mandatory ciphersuite TLS_RSA_WITH_AES_128_CBC_SHA");
        }
    }

}
