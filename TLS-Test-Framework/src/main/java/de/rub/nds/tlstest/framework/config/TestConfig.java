package de.rub.nds.tlstest.framework.config;

import com.beust.jcommander.ParametersDelegate;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.TLSDelegateConfig;
import de.rub.nds.tlsattacker.core.config.delegate.ClientDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.ServerDelegate;
import org.bouncycastle.util.IPAddress;

public class TestConfig extends TLSDelegateConfig {
    public ClientDelegate getClientDelegate() {
        return clientDelegate;
    }

    public ServerDelegate getServerDelegate() {
        return serverDelegate;
    }

    @ParametersDelegate
    private ClientDelegate clientDelegate;

    @ParametersDelegate
    private ServerDelegate serverDelegate;


    public TestConfig() {
        super(new GeneralDelegate());

        clientDelegate = new ClientDelegate();
        serverDelegate = new ServerDelegate();

        addDelegate(clientDelegate);
        addDelegate(serverDelegate);
    }


    @Override
    public Config createConfig(Config baseconfig) {
        Config config = super.createConfig(baseconfig);

        if (!IPAddress.isValid(config.getDefaultClientConnection().getHostname()) || clientDelegate.getSniHostname() != null) {
            config.setAddServerNameIndicationExtension(true);
        } else {
            config.setAddServerNameIndicationExtension(false);
        }

        return config;
    }
}
