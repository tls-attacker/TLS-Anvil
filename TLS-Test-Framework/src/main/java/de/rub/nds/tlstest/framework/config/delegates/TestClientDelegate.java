package de.rub.nds.tlstest.framework.config.delegates;

import com.beust.jcommander.Parameters;
import de.rub.nds.tlsattacker.core.config.delegate.ServerDelegate;

@Parameters(commandDescription = "Test a client implementation, thus start TLS-Attacker in server mode")
public class TestClientDelegate extends ServerDelegate {

}
