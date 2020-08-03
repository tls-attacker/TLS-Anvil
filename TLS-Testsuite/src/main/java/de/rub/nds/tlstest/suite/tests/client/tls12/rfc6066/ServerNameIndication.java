package de.rub.nds.tlstest.suite.tests.client.tls12.rfc6066;

import de.rub.nds.tlsattacker.core.constants.NameType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerNameIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.sni.ServerNamePair;
import de.rub.nds.tlstest.framework.annotations.MethodCondition;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.ServerTest;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;

import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertFalse;

@RFC(number = 6066, section = "3. Server Name Indication")
@ServerTest
public class ServerNameIndication extends Tls12Test {

    public ConditionEvaluationResult sniActive() {
        if (context.getReceivedClientHelloMessage().getExtension(ServerNameIndicationExtensionMessage.class) != null) {
            return ConditionEvaluationResult.enabled("");
        }
        return ConditionEvaluationResult.disabled("SNI is disabled");
    }

    @TlsTest(description = "The ServerNameList MUST NOT contain more than one name of the same " +
            "name_type.")
    @MethodCondition(method = "sniActive")
    public void moreThanOneNameOfTheSameType(WorkflowRunner runner) {
        ServerNameIndicationExtensionMessage ext = context.getReceivedClientHelloMessage().getExtension(ServerNameIndicationExtensionMessage.class);
        List<ServerNamePair> snis = ext.getServerNameList();

        List<NameType> nameTypes = new ArrayList<>();
        for (ServerNamePair i : snis) {
            NameType name = NameType.getNameType(i.getServerNameType().getValue());
            assertFalse("More than one name of the same name_type", nameTypes.contains(name));
            nameTypes.add(name);
        }
    }

}
