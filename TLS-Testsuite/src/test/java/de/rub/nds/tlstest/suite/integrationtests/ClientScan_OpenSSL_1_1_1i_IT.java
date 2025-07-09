package de.rub.nds.tlstest.suite.integrationtests;

import de.rub.nds.anvilcore.context.AnvilTestConfig;
import de.rub.nds.tls.subject.TlsImplementationType;
import de.rub.nds.tlstest.framework.config.TlsAnvilConfig;
import de.rub.nds.tlstest.suite.integrationtests.abstracts.AbstractClientScanIT;

public class ClientScan_OpenSSL_1_1_1i_IT extends AbstractClientScanIT {

    public ClientScan_OpenSSL_1_1_1i_IT() {
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
        tlsConfig.setParallelHandshakes(3);
    }
}
