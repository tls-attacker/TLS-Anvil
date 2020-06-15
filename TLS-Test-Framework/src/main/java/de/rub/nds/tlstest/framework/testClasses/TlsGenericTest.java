package de.rub.nds.tlstest.framework.testClasses;


import de.rub.nds.tlsattacker.core.config.Config;

public class TlsGenericTest extends TlsBaseTest {
    @Override
    public Config getConfig() {
        throw new RuntimeException("Invalid method, call context.getConfig.createConfig() instead");
    }
}
