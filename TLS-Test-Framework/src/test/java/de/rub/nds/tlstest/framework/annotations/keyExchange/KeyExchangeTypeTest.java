package de.rub.nds.tlstest.framework.annotations.keyExchange;


import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.utils.ExtensionContextResolver;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.ExtensionContext;
import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.HashSet;

@ExtendWith(ExtensionContextResolver.class)
public class KeyExchangeTypeTest {

    @BeforeAll
    public static void setup() {
        TestContext context = new TestContext();
        SiteReport siteReport = new SiteReport("", new ArrayList<>());

        siteReport.setCipherSuites(new HashSet<CipherSuite>(){
            {
                add(CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA);
            }
        });

        context.getConfig().setSiteReport(siteReport);
    }


    @Test
    @KeyExchange(provided = KeyExchangeType.RSA)
    public void test_resolve_providedSupported(ExtensionContext context) {
        KeyExchange resolved = KeyExchangeType.resolveKexAnnotation(context);

        assertEquals(resolved.provided(), KeyExchangeType.RSA);
        assertEquals(resolved.supported().length, 1);
        assertEquals(resolved.supported()[0], KeyExchangeType.RSA);
    }

    @Test
    @KeyExchange(provided = KeyExchangeType.DH)
    public void test_resolve_providedUnsupported(ExtensionContext context) {
        KeyExchange resolved = KeyExchangeType.resolveKexAnnotation(context);

        assertEquals(resolved.provided(), KeyExchangeType.DH);
        assertEquals(resolved.supported().length, 0);
    }


    @Test
    @KeyExchange(provided = KeyExchangeType.DH, supported = KeyExchangeType.RSA)
    public void test_resolve_providedUnsupportedSingleSupported(ExtensionContext context) {
        KeyExchange resolved = KeyExchangeType.resolveKexAnnotation(context);

        assertEquals(resolved.provided(), KeyExchangeType.DH);
        assertEquals(resolved.supported().length, 1);
        assertEquals(resolved.supported()[0], KeyExchangeType.RSA);
    }

    @Test
    @KeyExchange(provided = KeyExchangeType.DH, supported = { KeyExchangeType.RSA, KeyExchangeType.ECDH })
    public void test_resolve_providedUnsupportedMultipleSupported(ExtensionContext context) {
        KeyExchange resolved = KeyExchangeType.resolveKexAnnotation(context);

        assertEquals(resolved.provided(), KeyExchangeType.DH);
        assertEquals(resolved.supported().length, 1);
        assertEquals(resolved.supported()[0], KeyExchangeType.RSA);
    }

    @Test
    @KeyExchange(provided = KeyExchangeType.DH, supported = { KeyExchangeType.TLS13, KeyExchangeType.ECDH })
    public void test_resolve_providedUnsupportedUnsupportedSupported(ExtensionContext context) {
        KeyExchange resolved = KeyExchangeType.resolveKexAnnotation(context);

        assertEquals(resolved.provided(), KeyExchangeType.DH);
        assertEquals(resolved.supported().length, 0);
    }

    @Test
    @KeyExchange(provided = KeyExchangeType.DH, supported = { KeyExchangeType.ALL12 })
    public void test_resolve_providedUnsupportedSupportedAll(ExtensionContext context) {
        KeyExchange resolved = KeyExchangeType.resolveKexAnnotation(context);

        assertEquals(resolved.provided(), KeyExchangeType.DH);
        assertEquals(resolved.supported().length, 1);
        assertEquals(resolved.supported()[0], KeyExchangeType.RSA);
    }

    @Test
    @KeyExchange(provided = KeyExchangeType.RSA, supported = { KeyExchangeType.ECDH })
    public void test_resolve_providedSupportedUnsupportedSupported(ExtensionContext context) {
        KeyExchange resolved = KeyExchangeType.resolveKexAnnotation(context);

        assertEquals(resolved.provided(), KeyExchangeType.RSA);
        assertEquals(resolved.supported().length, 1);
        assertEquals(resolved.supported()[0], KeyExchangeType.RSA);
    }

    @Test
    @KeyExchange(provided = KeyExchangeType.ALL12, supported = { KeyExchangeType.ECDH })
    public void test_resolve_providedAllUnsupportedSupported(ExtensionContext context) {
        KeyExchange resolved = KeyExchangeType.resolveKexAnnotation(context);

        assertEquals(resolved.provided(), KeyExchangeType.ALL12);
        assertEquals(resolved.supported().length, 1);
        assertEquals(resolved.supported()[0], KeyExchangeType.RSA);
    }
}
