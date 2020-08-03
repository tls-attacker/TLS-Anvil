package de.rub.nds.tlstest.framework.annotations.keyExchange;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.TestSiteReport;
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
        TestContext testContext = new TestContext();
        TestSiteReport report = new TestSiteReport("");

        report.addCipherSuites(new HashSet<CipherSuite>(){
            {
                add(CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA);
            }
        });

        testContext.getConfig().setSiteReport(report);
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
    @KeyExchange()
    public void not_execute_KexNotSupportedByTarget() { }

    @TlsTest
    @KeyExchange(mergeSupportedWithClassSupported = true)
    public void not_execute_KexNotSupportedByTarget2() { }

    @TlsTest
    @KeyExchange(supported = KeyExchangeType.DH)
    public void not_execute_KexNotSupportedByTarget_setSupportedOnly() { }



}
