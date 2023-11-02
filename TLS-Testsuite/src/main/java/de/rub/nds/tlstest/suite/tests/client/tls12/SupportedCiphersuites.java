/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.client.tls12;

import static org.junit.Assert.assertEquals;

import de.rub.nds.anvilcore.annotation.ClientTest;
import de.rub.nds.anvilcore.annotation.NonCombinatorialAnvilTest;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Tag;

@ClientTest
public class SupportedCiphersuites extends Tls12Test {

    @NonCombinatorialAnvilTest(id = "XXX-GFtKDMr9x7")
    @Tag("ciphersuites")
    public void supportsMoreCiphersuitesThanAdvertised() {
        ClientHelloMessage clientHello = context.getReceivedClientHelloMessage();

        List<CipherSuite> advertised =
                CipherSuite.getCipherSuites(clientHello.getCipherSuites().getValue());
        List<CipherSuite> supported =
                new ArrayList<>(context.getFeatureExtractionResult().getCipherSuites());
        supported.addAll(context.getFeatureExtractionResult().getSupportedTls13CipherSuites());

        advertised.forEach(supported::remove);

        assertEquals(
                "Client supports more cipher suites than advertised. "
                        + supported.parallelStream()
                                .map(Enum::name)
                                .collect(Collectors.joining(",")),
                0,
                supported.size());
    }

    @NonCombinatorialAnvilTest(id = "XXX-DZsWLPbTuc")
    @Tag("ciphersuites")
    public void supportsLessCiphersuitesThanAdvertised() {
        ClientHelloMessage clientHello = context.getReceivedClientHelloMessage();

        List<CipherSuite> advertised =
                CipherSuite.getCipherSuites(clientHello.getCipherSuites().getValue());
        advertised.remove(CipherSuite.TLS_FALLBACK_SCSV);
        advertised.remove(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);

        List<CipherSuite> supported =
                new ArrayList<>(context.getFeatureExtractionResult().getCipherSuites());
        supported.addAll(context.getFeatureExtractionResult().getSupportedTls13CipherSuites());

        supported.forEach(advertised::remove);
        advertised =
                advertised.stream()
                        .filter(
                                cipherSuite ->
                                        CipherSuite.getImplemented().contains(cipherSuite)
                                                && !cipherSuite.isGOST())
                        .collect(Collectors.toList());

        assertEquals(
                "Client supports less ciphersuites than advertised. "
                        + advertised.parallelStream()
                                .map(Enum::name)
                                .collect(Collectors.joining(",")),
                0,
                advertised.size());
    }
}
