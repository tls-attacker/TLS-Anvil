
package de.rub.nds.tlstest.suite.tests.client.tls12.rfc7507;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlstest.framework.annotations.ClientTest;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.TestDescription;
import de.rub.nds.tlstest.framework.annotations.categories.ComplianceCategory;
import de.rub.nds.tlstest.framework.annotations.categories.HandshakeCategory;
import de.rub.nds.tlstest.framework.annotations.categories.SecurityCategory;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import java.util.List;
import static org.junit.Assert.assertFalse;
import org.junit.jupiter.api.Tag;

import org.junit.jupiter.api.Test;

@ClientTest
@RFC(number = 7507, section = "4. Client Behavior")
public class SCSV extends Tls12Test {
    @Test
    @TestDescription("If a client sets ClientHello.client_version to its highest " +
        "supported protocol version, it MUST NOT include TLS_FALLBACK_SCSV " +
        "in ClientHello.cipher_suites.")
    @SecurityCategory(SeverityLevel.HIGH)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    @Tag("new")
    public void doesNotIncludeFallbackCipherSuite() {
        ClientHelloMessage clientHello = context.getReceivedClientHelloMessage();

        List<CipherSuite> advertised = CipherSuite.getCipherSuites(clientHello.getCipherSuites().getValue());
        assertFalse("Client included TLS_FALLBACK_SCSV in its first ClientHello", advertised.contains(CipherSuite.TLS_FALLBACK_SCSV));
    }
}
