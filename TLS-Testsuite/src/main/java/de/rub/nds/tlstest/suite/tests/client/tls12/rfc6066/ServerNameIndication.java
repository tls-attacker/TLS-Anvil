/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.client.tls12.rfc6066;

import static org.junit.Assert.assertFalse;

import de.rub.nds.anvilcore.annotation.ClientTest;
import de.rub.nds.anvilcore.annotation.MethodCondition;
import de.rub.nds.anvilcore.annotation.NonCombinatorialAnvilTest;
import de.rub.nds.tlsattacker.core.constants.NameType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerNameIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.sni.ServerNamePair;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;

@ClientTest
public class ServerNameIndication extends Tls12Test {

    public ConditionEvaluationResult sniActive() {
        if (context.getReceivedClientHelloMessage()
                        .getExtension(ServerNameIndicationExtensionMessage.class)
                != null) {
            return ConditionEvaluationResult.enabled("");
        }
        return ConditionEvaluationResult.disabled("SNI is disabled");
    }

    @NonCombinatorialAnvilTest(id = "6066-E12eJCyta7")
    @MethodCondition(method = "sniActive")
    public void moreThanOneNameOfTheSameType() {
        ServerNameIndicationExtensionMessage ext =
                context.getReceivedClientHelloMessage()
                        .getExtension(ServerNameIndicationExtensionMessage.class);
        List<ServerNamePair> snis = ext.getServerNameList();

        List<NameType> nameTypes = new ArrayList<>();
        for (ServerNamePair i : snis) {
            NameType name = NameType.getNameType(i.getServerNameType().getValue());
            assertFalse("More than one name of the same name_type", nameTypes.contains(name));
            nameTypes.add(name);
        }
    }
}
