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

import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsscanner.serverscanner.report.result.VersionSuiteListPair;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.TestDescription;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.annotations.categories.Security;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.Assert.assertEquals;
import org.junit.Test;

@RFC(number = 5264, section = "1.2 Major Differences from TLS 1.1")
public class CipherSuites extends Tls12Test {

    //@TlsTest(description = "Removed IDEA and DES cipher suites. They are now deprecated and will be documented in a separate document.", )
    @Test
    @Security(SeverityLevel.CRITICAL)
    @TestDescription("IDEA and DES cipher suites must not be used for TLS 1.2")
    public void supportOfDeprectedCipherSuites() {
        List<VersionSuiteListPair> versionSuiteListPairList = context.getSiteReport().getVersionSuitePairs();
        List<CipherSuite> suites = versionSuiteListPairList.stream()
                .filter(i -> i.getVersion() == ProtocolVersion.TLS12)
                .flatMap(i -> i.getCiphersuiteList().stream())
                .collect(Collectors.toList());

        List<String> badSuites = new ArrayList<>();
        for (CipherSuite i : suites) {
            if (AlgorithmResolver.getCipher(i).toString().contains("IDEA")) {
                badSuites.add(i.toString());
            }
            else if (AlgorithmResolver.getCipher(i).toString().contains("DES")) {
                badSuites.add(i.toString());
            }
            else if (AlgorithmResolver.getCipher(i).toString().contains("RC4")) {
                badSuites.add(i.toString());
            }
        }

        assertEquals("Deprecated Ciphersuites supported: " + String.join(", ", badSuites), 0, badSuites.size());
    }
}
