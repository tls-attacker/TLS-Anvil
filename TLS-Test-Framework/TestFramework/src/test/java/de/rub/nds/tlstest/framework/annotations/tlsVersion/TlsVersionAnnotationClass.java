/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.annotations.tlsVersion;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.annotations.TlsVersion;

@TlsVersion(supported = ProtocolVersion.TLS12)
public class TlsVersionAnnotationClass extends TlsVersionTest {

    @TlsTest
    @TlsVersion(supported = ProtocolVersion.TLS12)
    public void execute_supported() {}

    @TlsTest
    public void execute_inheritedClassAnnotation() {}

    @TlsTest
    @TlsVersion(supported = ProtocolVersion.SSL3)
    public void execute_supported_overwrittenClassAnnotation() {}

    @TlsTest
    @TlsVersion(supported = ProtocolVersion.TLS13)
    public void not_execute_unsupported() {}
}
