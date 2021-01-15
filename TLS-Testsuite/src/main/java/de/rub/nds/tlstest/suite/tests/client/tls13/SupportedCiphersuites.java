/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.client.tls13;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlstest.framework.annotations.ClientTest;
import de.rub.nds.tlstest.framework.annotations.TestDescription;
import de.rub.nds.tlstest.framework.annotations.categories.Compliance;
import de.rub.nds.tlstest.framework.annotations.categories.Handshake;
import de.rub.nds.tlstest.framework.annotations.categories.Interoperability;
import de.rub.nds.tlstest.framework.annotations.categories.Security;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.Assert.assertEquals;
import org.junit.jupiter.api.Test;

@ClientTest
public class SupportedCiphersuites extends Tls13Test {

    @Test
    @TestDescription("Client exploration detected more supported ciphersuites than "
            + "advertised by the client in the ClientHello message.")
    @Handshake(SeverityLevel.MEDIUM)
    @Compliance(SeverityLevel.HIGH)
    @Security(SeverityLevel.HIGH)
    public void supportsMoreCiphersuitesThanAdvertised() {
        ClientHelloMessage clientHello = context.getReceivedClientHelloMessage();

        List<CipherSuite> advertised = CipherSuite.getCipherSuites(clientHello.getCipherSuites().getValue());
        List<CipherSuite> supported = new ArrayList<>(context.getSiteReport().getSupportedTls13CipherSuites());

        advertised.forEach(supported::remove);

        assertEquals("Client supports more ciphersuites than advertised. "
                + supported.parallelStream().map(Enum::name).collect(Collectors.joining(",")),
                0,
                supported.size());
    }
}
