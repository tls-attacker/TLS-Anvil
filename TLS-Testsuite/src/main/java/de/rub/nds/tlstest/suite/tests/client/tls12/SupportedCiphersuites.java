package de.rub.nds.tlstest.suite.tests.client.tls12;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlstest.framework.annotations.ClientTest;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import org.junit.jupiter.api.Tag;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.Assert.assertEquals;

@ClientTest
public class SupportedCiphersuites extends Tls12Test {

    @TlsTest(description = "Client exploration detected moresupported ciphersuites than " +
            "advertised by the client in the ClientHello message.", securitySeverity = SeverityLevel.MEDIUM)
    @Tag("ciphersuites")
    public void supportsMoreCiphersuitesThanAdvertised() {
        ClientHelloMessage clientHello = context.getReceivedClientHelloMessage();

        List<CipherSuite> advertised = CipherSuite.getCiphersuites(clientHello.getCipherSuites().getValue());
        List<CipherSuite> supported = new ArrayList<>(context.getSiteReport().getCipherSuites());
        supported.addAll(context.getSiteReport().getSupportedTls13CipherSuites());

        advertised.forEach(supported::remove);

        assertEquals("Client supports more ciphersuites than advertised. " +
                        supported.parallelStream().map(Enum::name).collect(Collectors.joining(",")),
                0,
                supported.size());
    }


    @TlsTest(description = "Client exploration detected less supported ciphersuites than " +
            "advertised by the client in the ClientHello message.", interoperabilitySeverity = SeverityLevel.HIGH)
    @Tag("ciphersuites")
    public void supportsLessCiphersuitesThanAdvertised() {
        ClientHelloMessage clientHello = context.getReceivedClientHelloMessage();

        List<CipherSuite> advertised = CipherSuite.getCiphersuites(clientHello.getCipherSuites().getValue());
        advertised.remove(CipherSuite.TLS_FALLBACK_SCSV);
        advertised.remove(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);

        List<CipherSuite> supported = new ArrayList<>(context.getSiteReport().getCipherSuites());
        supported.addAll(context.getSiteReport().getSupportedTls13CipherSuites());

        supported.forEach(advertised::remove);

        assertEquals("Client supports less ciphersuites than advertised. " +
                        advertised.parallelStream().map(Enum::name).collect(Collectors.joining(",")),
                0,
                advertised.size());
    }
}

