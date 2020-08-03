package de.rub.nds.tlstest.suite.tests.client.tls13.rfc8446;

import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PreSharedKeyExtensionMessage;
import de.rub.nds.tlstest.framework.annotations.ClientTest;
import de.rub.nds.tlstest.framework.annotations.MethodCondition;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
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

    // TODO: Server test is missing
    @TlsTest(description = "The \"pre_shared_key\" extension MUST be the last extension " +
            "in the ClientHello (this facilitates implementation as described below). " +
            "Servers MUST check that it is the last extension and otherwise fail " +
            "the handshake with an \"illegal_parameter\" alert.")
    @MethodCondition(method = "sendsPSKExtension")
    public void isLastExtension() {
        ClientHelloMessage chm = context.getReceivedClientHelloMessage();
        if (!chm.getExtensions().get(chm.getExtensions().size() - 1).getClass().equals(PreSharedKeyExtensionMessage.class)) {
            throw new AssertionError("PreSharedKeyExtensionMessage is not the last extension");
        }
    }
}
