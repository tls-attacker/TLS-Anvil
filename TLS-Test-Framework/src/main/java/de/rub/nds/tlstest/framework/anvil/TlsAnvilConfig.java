package de.rub.nds.tlstest.framework.anvil;

import de.rub.nds.anvilcore.model.config.AnvilConfig;
import de.rub.nds.tlsattacker.core.config.Config;

public class TlsAnvilConfig implements AnvilConfig {

    private final Config tlsConfig;

    // todo AnvilConfig should be replaced with an interface on ProtocolAttacker level
    public TlsAnvilConfig(Config tlsConfig) {
        this.tlsConfig = tlsConfig;
    }

    public Config getTlsConfig() {
        return tlsConfig;
    }
}
