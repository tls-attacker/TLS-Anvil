/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * Copyright 2022 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.annotations.keyExchange;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.ServerTestSiteReport;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.junitExtensions.KexCondition;
import de.rub.nds.tlstest.framework.utils.ConditionTest;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.util.HashSet;


public class KexAnnotationMethodTest {

    @RegisterExtension
    static ConditionTest ext = new ConditionTest(KexCondition.class);

    @BeforeAll
    static void setup() {
        TestContext testContext = TestContext.getInstance();
        ServerTestSiteReport report = new ServerTestSiteReport("");

        report.addCipherSuites(new HashSet<CipherSuite>(){
            {
                add(CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA);
            }
        });

        testContext.setSiteReport(report);
    }

    @TlsTest
    @KeyExchange(supported = { KeyExchangeType.ECDH })
    public void execute_SupportedSupported() { }

    @TlsTest
    @KeyExchange(supported = { KeyExchangeType.ALL12 })
    public void execute_allSupported() { }

    @TlsTest
    @KeyExchange(supported = {KeyExchangeType.DH, KeyExchangeType.ECDH})
    public void execute_multipleSupported() { }



    @TlsTest
    public void execute_noKexAnnotationSpecified() { }

    @TlsTest
    @KeyExchange(supported = {}, mergeSupportedWithClassSupported = true)
    public void not_execute_KexNotSupportedByTarget2() { }

    @TlsTest
    @KeyExchange(supported = KeyExchangeType.DH)
    public void not_execute_KexNotSupportedByTarget_setSupportedOnly() { }



}
