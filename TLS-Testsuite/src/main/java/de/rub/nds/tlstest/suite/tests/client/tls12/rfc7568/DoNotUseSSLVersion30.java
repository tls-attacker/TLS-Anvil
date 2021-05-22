/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.client.tls12.rfc7568;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlstest.framework.annotations.ClientTest;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.TestDescription;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.annotations.categories.DeprecatedFeatureCategory;
import de.rub.nds.tlstest.framework.annotations.categories.HandshakeCategory;
import de.rub.nds.tlstest.framework.annotations.categories.SecurityCategory;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;

import java.util.Arrays;

import static org.junit.Assert.*;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

@RFC(number = 7568, section = "3. Do Not Use SSL Version 3.0")
@ClientTest
public class DoNotUseSSLVersion30 extends Tls12Test {

    @Test
    @TestDescription("SSLv3 MUST NOT be used. Negotiation of SSLv3 from "
            + "any version of TLS MUST NOT be permitted. "
            + "Pragmatically, clients MUST NOT send a ClientHello with "
            + "ClientHello.client_version set to {03,00}.")
    @SecurityCategory(SeverityLevel.CRITICAL)
    @DeprecatedFeatureCategory(SeverityLevel.CRITICAL)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    public void sendClientHelloVersion0300() {
        ClientHelloMessage clientHelloMessage = context.getReceivedClientHelloMessage();
        assertFalse("ClientHello contains protocol version 0300",
                Arrays.equals(ProtocolVersion.SSL3.getValue(), clientHelloMessage.getProtocolVersion().getValue())
        );
    }
}
