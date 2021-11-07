/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.annotations.keyExchange;


import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.TestSiteReport;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.constants.KeyX;
import de.rub.nds.tlstest.framework.utils.ExtensionContextResolver;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.ExtensionContext;

import java.util.HashSet;

import static org.junit.Assert.assertEquals;

@ExtendWith(ExtensionContextResolver.class)
public class KeyXResolveTest {

    @BeforeAll
    public static void setup() {
        TestContext context = TestContext.getInstance();
        TestSiteReport siteReport = new TestSiteReport("");

        siteReport.addCipherSuites(new HashSet<CipherSuite>(){
            {
                add(CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA);
            }
        });

        context.setSiteReport(siteReport);
    }


    @Test
    @KeyExchange(supported = KeyExchangeType.RSA)
    public void test_resolve_singleSupported(ExtensionContext context) {
        KeyExchange resolved = KeyX.resolveKexAnnotation(context);

        assertEquals(resolved.supported().length, 1);
        assertEquals(resolved.supported()[0], KeyExchangeType.RSA);
    }

    @Test
    @KeyExchange(supported = {})
    public void test_resolve_withoutSupported(ExtensionContext context) {
        KeyExchange resolved = KeyX.resolveKexAnnotation(context);
        assertEquals(resolved.supported().length, 0);
    }


    @Test
    @KeyExchange(supported = { KeyExchangeType.RSA, KeyExchangeType.ECDH })
    public void test_resolve_multipleSupported(ExtensionContext context) {
        KeyExchange resolved = KeyX.resolveKexAnnotation(context);

        assertEquals(resolved.supported().length, 1);
        assertEquals(resolved.supported()[0], KeyExchangeType.RSA);
    }

    @Test
    @KeyExchange(supported = { KeyExchangeType.ALL13, KeyExchangeType.ECDH })
    public void test_resolve_unsupportedSupported(ExtensionContext context) {
        KeyExchange resolved = KeyX.resolveKexAnnotation(context);

        assertEquals(resolved.supported().length, 0);
    }

    @Test
    @KeyExchange(supported = { KeyExchangeType.ALL12 })
    public void test_resolve_supportedAll(ExtensionContext context) {
        KeyExchange resolved = KeyX.resolveKexAnnotation(context);

        assertEquals(resolved.supported().length, 1);
        assertEquals(resolved.supported()[0], KeyExchangeType.RSA);
    }

    @Test
    @KeyExchange(supported = { KeyExchangeType.ECDH }, requiresServerKeyExchMsg = true)
    public void test_resolve_requiresServerKeyExchMsg(ExtensionContext context) {
        KeyExchange resolved = KeyX.resolveKexAnnotation(context);

        assertEquals(resolved.supported().length, 0);
    }
}
