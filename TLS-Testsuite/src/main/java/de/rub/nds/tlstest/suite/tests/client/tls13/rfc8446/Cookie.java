/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.client.tls13.rfc8446;

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlstest.framework.annotations.ClientTest;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;

import java.util.Arrays;

@ClientTest
@RFC(number = 8446, section = "4.2.2 Cookie")
public class Cookie extends Tls13Test {

    @TlsTest(description = "Clients MUST NOT use cookies in their initial ClientHello in subsequent connections.")
    public void clientHelloContainsCookieExtension() {
        int size = (int) context.getReceivedClientHelloMessage().getExtensions().stream()
                .filter(i -> Arrays.equals(ExtensionType.COOKIE.getValue(), i.getExtensionType().getValue())).count();
        if (size > 0) {
            throw new AssertionError("Regular ClientHello contains Cookie extension");
        }
    }
}
