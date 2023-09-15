/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.client.tls12.rfc7685;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotNull;

import de.rub.nds.anvilcore.annotation.ClientTest;
import de.rub.nds.anvilcore.annotation.MethodCondition;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PaddingExtensionMessage;
import de.rub.nds.tlstest.framework.constants.AssertMsgs;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;

@ClientTest
public class PaddingExtension extends Tls12Test {

    public ConditionEvaluationResult offeredExtension() {
        if (context.getReceivedClientHelloMessage().containsExtension(ExtensionType.PADDING)) {
            return ConditionEvaluationResult.enabled("The Extension can be evaluated");
        }
        return ConditionEvaluationResult.disabled(
                "Extension has not been offered and can not be evaluated");
    }

    @Test
    @MethodCondition(method = "offeredExtension")
    public void paddingWithNonZero() {
        ClientHelloMessage msg = context.getReceivedClientHelloMessage();
        assertNotNull(AssertMsgs.CLIENT_HELLO_NOT_RECEIVED, msg);

        PaddingExtensionMessage paddingExt = msg.getExtension(PaddingExtensionMessage.class);

        byte[] receivedPaddingExt = paddingExt.getPaddingBytes().getValue();
        byte[] expected = new byte[receivedPaddingExt.length];
        assertArrayEquals("Padding extension padding bytes not zero", expected, receivedPaddingExt);
    }
}
