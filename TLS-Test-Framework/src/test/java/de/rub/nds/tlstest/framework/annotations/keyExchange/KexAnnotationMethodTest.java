package de.rub.nds.tlstest.framework.annotations.keyExchange;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.utils.ConditionTest;
import de.rub.nds.tlstest.framework.junitExtensions.KexCondition;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.util.ArrayList;
import java.util.HashSet;


public class KexAnnotationMethodTest {

    @RegisterExtension
    static ConditionTest ext = new ConditionTest(KexCondition.class);

    @BeforeAll
    static void setup() {
        TestContext testContext = new TestContext();
        SiteReport report = new SiteReport("", new ArrayList<>());

        report.setCipherSuites(new HashSet<CipherSuite>(){
            {
                add(CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA);
            }
        });

        testContext.getConfig().setSiteReport(report);
    }

    @TlsTest
    @KeyExchange(provided = KeyExchangeType.DH, supported = { KeyExchangeType.ECDH })
    public void execute_unsupportedProvided_but_SupportedSupported() { }

    @TlsTest
    @KeyExchange(provided = KeyExchangeType.DH, supported = { KeyExchangeType.ALL12 })
    public void execute_unsupportedProvided_but_allSupported() { }


    @TlsTest
    @KeyExchange(provided = KeyExchangeType.ECDH, supported = { KeyExchangeType.DH })
    public void execute_supportedProvided_but_UnsupportedSupported() { }

    @TlsTest
    @KeyExchange(supported = {KeyExchangeType.DH, KeyExchangeType.ECDH})
    public void execute_noProvided_multipleSupported() { }

    @TlsTest
    @KeyExchange(supported = KeyExchangeType.ECDH)
    public void execute_KexSupportedByTarget_setSupportedOnly() { }



    @TlsTest
    public void execute_noKexAnnotationSpecified() { }

    @TlsTest
    @KeyExchange(provided = KeyExchangeType.DH)
    public void not_execute_KexNotSupportedByTarget() { }

    @TlsTest
    @KeyExchange(provided = KeyExchangeType.DH, mergeSupportedWithClassSupported = true)
    public void not_execute_KexNotSupportedByTarget2() { }

    @TlsTest
    @KeyExchange(supported = KeyExchangeType.DH)
    public void not_execute_KexNotSupportedByTarget_setSupportedOnly() { }



}
