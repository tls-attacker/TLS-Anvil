/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.client.tls13.rfc8446;

import de.rub.nds.anvilcore.annotation.ClientTest;
import de.rub.nds.anvilcore.annotation.MethodCondition;
import de.rub.nds.anvilcore.annotation.NonCombinatorialAnvilTest;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PreSharedKeyExtensionMessage;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;

@ClientTest
public class PreSharedKey extends Tls13Test {

    public ConditionEvaluationResult sendsPSKExtension() {
        if (context.getReceivedClientHelloMessage().getExtension(PreSharedKeyExtensionMessage.class)
                != null) {
            return ConditionEvaluationResult.enabled("");
        }
        return ConditionEvaluationResult.disabled("Client does not support PreSharedKeyExtension");
    }

    /*@AnvilTest. " +
    "Servers MUST check that it is the last extension and otherwise fail " +
    "the handshake with an \"illegal_parameter\" alert.")*/
    @NonCombinatorialAnvilTest
    @MethodCondition(method = "sendsPSKExtension")
    @Disabled
    public void isLastExtension() {
        ClientHelloMessage chm = context.getReceivedClientHelloMessage();
        if (!chm.getExtensions()
                .get(chm.getExtensions().size() - 1)
                .getClass()
                .equals(PreSharedKeyExtensionMessage.class)) {
            throw new AssertionError("PreSharedKeyExtensionMessage is not the last extension");
        }
    }
}
