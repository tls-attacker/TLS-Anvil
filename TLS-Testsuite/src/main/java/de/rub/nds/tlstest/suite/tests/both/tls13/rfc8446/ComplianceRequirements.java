/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.both.tls13.rfc8446;

import static org.junit.Assert.assertTrue;

import de.rub.nds.anvilcore.annotation.NonCombinatorialAnvilTest;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
import org.junit.jupiter.api.Tag;

public class ComplianceRequirements extends Tls13Test {
    @NonCombinatorialAnvilTest
    @Tag("new")
    public void supportsAes128GcmSha256() {
        assertTrue(
                "Peer does not support TLS_AES_128_GCM_SHA256 ",
                context.getFeatureExtractionResult()
                        .getSupportedTls13CipherSuites()
                        .contains(CipherSuite.TLS_AES_128_GCM_SHA256));
    }

    @NonCombinatorialAnvilTest
    @Tag("new")
    public void supportsSecp256r1() {
        assertTrue(
                "Peer does not support secp256r1",
                context.getFeatureExtractionResult()
                        .getTls13Groups()
                        .contains(NamedGroup.SECP256R1));
    }
}
