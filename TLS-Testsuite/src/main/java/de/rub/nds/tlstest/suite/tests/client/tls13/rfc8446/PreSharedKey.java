/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.client.tls13.rfc8446;

import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PreSharedKeyExtensionMessage;
import de.rub.nds.tlstest.framework.annotations.ClientTest;
import de.rub.nds.tlstest.framework.annotations.MethodCondition;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.TestDescription;
import de.rub.nds.tlstest.framework.annotations.categories.AlertCategory;
import de.rub.nds.tlstest.framework.annotations.categories.ComplianceCategory;
import de.rub.nds.tlstest.framework.annotations.categories.CryptoCategory;
import de.rub.nds.tlstest.framework.annotations.categories.DeprecatedFeatureCategory;
import de.rub.nds.tlstest.framework.annotations.categories.HandshakeCategory;
import de.rub.nds.tlstest.framework.annotations.categories.InteroperabilityCategory;
import de.rub.nds.tlstest.framework.annotations.categories.MessageStructureCategory;
import de.rub.nds.tlstest.framework.annotations.categories.SecurityCategory;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;

@ClientTest
@RFC(number = 8446, section = "4.2.11. Pre-Shared Key Extension")
public class PreSharedKey extends Tls13Test {

    public ConditionEvaluationResult sendsPSKExtension() {
        if (context.getReceivedClientHelloMessage().getExtension(PreSharedKeyExtensionMessage.class) != null) {
            return ConditionEvaluationResult.enabled("");
        }
        return ConditionEvaluationResult.disabled("Client does not support PreSharedKeyExtension");
    }

    /*@TlsTest(description = "The \"pre_shared_key\" extension MUST be the last extension " +
            "in the ClientHello (this facilitates implementation as described below). " +
            "Servers MUST check that it is the last extension and otherwise fail " +
            "the handshake with an \"illegal_parameter\" alert.")*/
    @Test
    @MethodCondition(method = "sendsPSKExtension")
    @TestDescription("The Pre-Shared Key extension must be the last extension of the Client Hello")
    @InteroperabilityCategory(SeverityLevel.HIGH)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    @SecurityCategory(SeverityLevel.HIGH)
    public void isLastExtension() {
        ClientHelloMessage chm = context.getReceivedClientHelloMessage();
        if (!chm.getExtensions().get(chm.getExtensions().size() - 1).getClass().equals(PreSharedKeyExtensionMessage.class)) {
            throw new AssertionError("PreSharedKeyExtensionMessage is not the last extension");
        }
    }
}
