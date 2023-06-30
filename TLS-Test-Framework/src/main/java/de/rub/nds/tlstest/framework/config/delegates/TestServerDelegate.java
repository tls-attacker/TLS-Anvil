/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.config.delegates;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.Parameters;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.ClientDelegate;
import org.bouncycastle.util.IPAddress;

@Parameters(
        commandDescription =
                "Test a server implementation, thus start TLS-Attacker in client mode.")
public class TestServerDelegate extends ClientDelegate {

    @Parameter(
            names = "-doNotSendSNIExtension",
            description =
                    "Usually the hostname for the SNI extension is inferred automatically. "
                            + "This option can overwrite the default behaviour.")
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

        if ((!IPAddress.isValid(config.getDefaultClientConnection().getHostname())
                        || this.getSniHostname() != null)
                && !doNotSendSNIExtension) {
            config.setAddServerNameIndicationExtension(true);
        } else {
            config.setAddServerNameIndicationExtension(false);
        }
    }
}
