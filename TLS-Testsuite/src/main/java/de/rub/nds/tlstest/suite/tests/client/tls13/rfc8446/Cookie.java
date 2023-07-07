/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.client.tls13.rfc8446;

import de.rub.nds.anvilcore.annotation.TestDescription;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlstest.framework.annotations.ClientTest;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.categories.ComplianceCategory;
import de.rub.nds.tlstest.framework.annotations.categories.HandshakeCategory;
import de.rub.nds.tlstest.framework.annotations.categories.InteroperabilityCategory;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

@ClientTest
@RFC(number = 8446, section = "4.2.2 Cookie")
public class Cookie extends Tls13Test {

    @Test
    @TestDescription(
            "Clients MUST NOT use cookies in their initial ClientHello in subsequent connections.")
    @InteroperabilityCategory(SeverityLevel.MEDIUM)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.MEDIUM)
    public void clientHelloContainsCookieExtension() {
        int size =
                (int)
                        context.getReceivedClientHelloMessage().getExtensions().stream()
                                .filter(
                                        i ->
                                                Arrays.equals(
                                                        ExtensionType.COOKIE.getValue(),
                                                        i.getExtensionType().getValue()))
                                .count();
        if (size > 0) {
            throw new AssertionError("Regular ClientHello contains Cookie extension");
        }
    }
}
