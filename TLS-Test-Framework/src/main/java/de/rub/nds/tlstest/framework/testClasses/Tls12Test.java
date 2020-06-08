package de.rub.nds.tlstest.framework.testClasses;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlstest.framework.annotations.TlsVersion;

@TlsVersion(supported = ProtocolVersion.TLS12)
public class Tls12Test extends TlsBaseTest {
    @Override
    public Config getConfig() {
        return context.getConfig().createConfig();
    }
}
