/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.client.tls12.rfc7568;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.anvilcore.annotation.ClientTest;
import de.rub.nds.anvilcore.annotation.NonCombinatorialAnvilTest;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import java.util.Arrays;

@ClientTest
public class DoNotUseSSLVersion30 extends Tls12Test {

    @NonCombinatorialAnvilTest(id = "7568-BiD6J3KQPu")
    public void sendClientHelloVersion0300() {
        ClientHelloMessage clientHelloMessage = context.getReceivedClientHelloMessage();
        assertFalse(
                Arrays.equals(
                        ProtocolVersion.SSL3.getValue(),
                        clientHelloMessage.getProtocolVersion().getValue()),
                "ClientHello contains protocol version 0300");
    }
}
