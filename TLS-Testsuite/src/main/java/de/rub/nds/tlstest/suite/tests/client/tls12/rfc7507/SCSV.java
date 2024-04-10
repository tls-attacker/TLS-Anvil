/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.client.tls12.rfc7507;

import static org.junit.Assert.assertFalse;

import de.rub.nds.anvilcore.annotation.ClientTest;
import de.rub.nds.anvilcore.annotation.NonCombinatorialAnvilTest;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import java.util.List;
import org.junit.jupiter.api.Tag;

@ClientTest
public class SCSV extends Tls12Test {
    @NonCombinatorialAnvilTest(id = "7507-YMY8CHMEzt")
    @Tag("new")
    public void doesNotIncludeFallbackCipherSuite() {
        ClientHelloMessage clientHello = context.getReceivedClientHelloMessage();

        List<CipherSuite> advertised =
                CipherSuite.getCipherSuites(clientHello.getCipherSuites().getValue());
        assertFalse(
                "Client included TLS_FALLBACK_SCSV in its first ClientHello",
                advertised.contains(CipherSuite.TLS_FALLBACK_SCSV));
    }
}
