/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.client.tls12.rfc5246;

import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlstest.framework.annotations.ClientTest;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.TestDescription;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.annotations.categories.Alert;
import de.rub.nds.tlstest.framework.annotations.categories.Compliance;
import de.rub.nds.tlstest.framework.annotations.categories.Handshake;
import de.rub.nds.tlstest.framework.annotations.categories.Interoperability;
import de.rub.nds.tlstest.framework.annotations.categories.Security;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;

import static org.junit.Assert.assertTrue;
import org.junit.jupiter.api.Test;

@RFC(number = 5246, section = "7.4.1.2. Client Hello")
@ClientTest
public class ClientHello extends Tls12Test {

    @Test
    @TestDescription("This vector MUST contain, and all implementations MUST support, CompressionMethod.null. "
            + "Thus, a client and server will always be able to agree on a compression method.")
    @Interoperability(SeverityLevel.CRITICAL)
    @Security(SeverityLevel.MEDIUM)
    @Compliance(SeverityLevel.CRITICAL)
    @Handshake(SeverityLevel.MEDIUM)
    // TODO: ich bin mir noch nicht sicher, ob es andere Tests zu kompression gibt
    // aber eigentlich sollte man checken ob es etwsa ausser von 0 gibt. dann gibt
    // potentiell einen CRIME angriff und security ist CRITICAL
    public void unknownCompressionMethod() {
        ClientHelloMessage clientHelloMessage = context.getReceivedClientHelloMessage();
        byte[] compression = clientHelloMessage.getCompressions().getValue();
        boolean containsZero = false;
        for (byte i : compression) {
            if (i == 0) {
                containsZero = true;
                break;
            }
        }

        assertTrue("ClientHello does not contain compression method null", containsZero);
    }
}
