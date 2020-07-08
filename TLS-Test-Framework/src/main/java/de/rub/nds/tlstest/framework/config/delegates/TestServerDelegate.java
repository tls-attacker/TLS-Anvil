package de.rub.nds.tlstest.framework.config.delegates;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.Parameters;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.ClientDelegate;
import de.rub.nds.tlsattacker.core.constants.NameType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.sni.SNIEntry;
import de.rub.nds.tlstest.framework.constants.TestEndpointType;
import org.bouncycastle.util.IPAddress;

@Parameters(commandDescription = "Test a server implementation, thus start TLS-Attacker in client mode.")
public class TestServerDelegate extends ClientDelegate {

    @Parameter(names = "-doNotSendSNIExtension", description = "Usually the hostname for the SNI extension is inferred automatically. " +
            "This option can overwrite the default behaviour.")
    private boolean doNotSendSNIExtension = false;

    public boolean isDoNotSendSNIExtension() {
        return doNotSendSNIExtension;
    }

    public void setDoNotSendSNIExtension(boolean doNotSendSNIExtension) {
        this.doNotSendSNIExtension = doNotSendSNIExtension;
    }

    @Override
    public void applyDelegate(Config config) {
        super.applyDelegate(config);

        if ((!IPAddress.isValid(config.getDefaultClientConnection().getHostname()) || this.getSniHostname() != null)
                && !doNotSendSNIExtension) {
            config.setAddServerNameIndicationExtension(true);
            config.setDefaultClientSNIEntries(new SNIEntry(config.getDefaultClientConnection().getHostname(), NameType.HOST_NAME));
        } else {
            config.setAddServerNameIndicationExtension(false);
        }
    }
}
