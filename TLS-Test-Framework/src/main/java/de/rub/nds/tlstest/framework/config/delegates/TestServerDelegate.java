package de.rub.nds.tlstest.framework.config.delegates;

import com.beust.jcommander.Parameters;
import de.rub.nds.tlsattacker.core.config.delegate.ClientDelegate;

@Parameters(commandDescription = "Test a server implementation, thus start TLS-Attacker in client mode.")
public class TestServerDelegate extends ClientDelegate {

}
