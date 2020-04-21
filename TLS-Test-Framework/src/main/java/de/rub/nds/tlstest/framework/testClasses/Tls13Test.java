package de.rub.nds.tlstest.framework.testClasses;


import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlstest.framework.annotations.TlsVersion;

@TlsVersion(supported = ProtocolVersion.TLS13)
public class Tls13Test extends TlsBaseTest {

}
