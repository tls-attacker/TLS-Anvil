/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.client.tls13.rfc8446;

import static org.junit.Assert.assertEquals;

import de.rub.nds.anvilcore.annotation.ClientTest;
import de.rub.nds.anvilcore.annotation.NonCombinatorialAnvilTest;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Tag;

@ClientTest
public class SupportedCiphersuites extends Tls13Test {

    @NonCombinatorialAnvilTest(id = "8446-FnJguFLqcc")
    public void supportsMoreCipherSuitesThanAdvertised() {
        ClientHelloMessage clientHello = context.getReceivedClientHelloMessage();

        List<CipherSuite> advertised =
                CipherSuite.getCipherSuites(clientHello.getCipherSuites().getValue());
        List<CipherSuite> supported =
                new ArrayList<>(
                        context.getFeatureExtractionResult().getSupportedTls13CipherSuites());

        advertised.forEach(supported::remove);

        assertEquals(
                "Client supports more cipher suites than advertised. "
                        + supported.parallelStream()
                                .map(Enum::name)
                                .collect(Collectors.joining(",")),
                0,
                supported.size());
    }

    @NonCombinatorialAnvilTest(id = "8446-CFyJvy1SNZ")
    @Tag("new")
    public void supportsLessCipherSuitesThanAdvertised() {
        ClientHelloMessage clientHello = context.getReceivedClientHelloMessage();
        List<CipherSuite> advertised =
                CipherSuite.getCipherSuites(clientHello.getCipherSuites().getValue()).stream()
                        .filter(CipherSuite::isTls13)
                        .collect(Collectors.toList());
        List<CipherSuite> supported =
                new ArrayList<>(
                        context.getFeatureExtractionResult().getSupportedTls13CipherSuites());
        supported.forEach(advertised::remove);
        assertEquals(
                "Client supports less cipher suites than advertised. Unsupported: "
                        + advertised.parallelStream()
                                .map(Enum::name)
                                .collect(Collectors.joining(",")),
                0,
                advertised.size());
    }
}
