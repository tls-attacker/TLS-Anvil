package de.rub.nds.tlstest.suite.integrationtests;

import de.rub.nds.anvilcore.context.AnvilTestConfig;
import de.rub.nds.tls.subject.TlsImplementationType;
import de.rub.nds.tlstest.framework.config.TlsAnvilConfig;
import de.rub.nds.tlstest.framework.config.delegates.TestServerDelegate;
import de.rub.nds.tlstest.suite.integrationtests.abstracts.AbstractServerScanIT;

public class ServerScan_OpenSSL_1_1_1i_IT extends AbstractServerScanIT {

    public ServerScan_OpenSSL_1_1_1i_IT() {
        super(TlsImplementationType.OPENSSL, "1.1.1i");
    }

    @Override
    protected void setUpAnvilTestConfig(AnvilTestConfig anvilTestConfig) {
        anvilTestConfig.setParallelTests(2);
        anvilTestConfig.setStrength(1);
        anvilTestConfig.setConnectionTimeout(200);
    }

    @Override
    protected void setUpTlsTestConfig(TlsAnvilConfig tlsConfig) {
        tlsConfig.setParallelHandshakes(1);
    }

    protected void setUpServerDelegate(TestServerDelegate testServerDelegate) {
        testServerDelegate.setSniHostname("localhost");
        testServerDelegate.setDoNotSendSNIExtension(false);
        super.setUpServerDelegate(testServerDelegate);
    }
}
