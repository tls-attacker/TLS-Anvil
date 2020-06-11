package de.rub.nds.tlstest.suite.tests.both.tls12.rfc5246;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;

import java.util.ArrayList;
import java.util.List;


@RFC(number = 5246, section = "A.5. The Cipher Suite")
public class A5CipherSuite extends Tls12Test {

    @TlsTest(description = "TLS_NULL_WITH_NULL_NULL is specified and is the initial state of a TLS connection during " +
            "the first handshake on that channel, but MUST NOT be negotiated, as it provides no more protection " +
            "than an unsecured connection.", securitySeverity = SeverityLevel.CRITICAL)
    public void negotiateTLS_NULL_WITH_NULL_NULL() {
        List<CipherSuite> suites = new ArrayList<>(context.getConfig().getSiteReport().getCipherSuites());
        if (suites.contains(CipherSuite.TLS_NULL_WITH_NULL_NULL)) {
            throw new AssertionError("TLS_NULL_WITH_NULL_NULL ciphersuite is supported");
        }
    }

    @TlsTest(description = "These cipher suites MUST NOT be used by TLS 1.2 implementations unless the application " +
            "layer has specifically requested to allow anonymous key exchange")
    public void anonCipherSuites() {
        List<CipherSuite> suites = new ArrayList<>(context.getConfig().getSiteReport().getCipherSuites());
        List<CipherSuite> forbidden = CipherSuite.getImplemented();
        forbidden.removeIf(i -> !i.toString().contains("_anon_"));

        List<String> errors = new ArrayList<>();
        for (CipherSuite i : forbidden) {
            if (suites.contains(i)) {
                errors.add(i.toString());
            }
        }

        if (errors.size() > 0) {
            throw new AssertionError(String.format("The following ciphersuites should not be supported: %s", String.join(", ", errors)));
        }
    }


}
