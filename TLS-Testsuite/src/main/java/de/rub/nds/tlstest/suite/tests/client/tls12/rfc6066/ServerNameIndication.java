/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * Copyright 2022 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.client.tls12.rfc6066;

import de.rub.nds.tlsattacker.core.constants.NameType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerNameIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.sni.ServerNamePair;
import de.rub.nds.tlstest.framework.annotations.ClientTest;
import de.rub.nds.tlstest.framework.annotations.MethodCondition;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.TestDescription;
import de.rub.nds.tlstest.framework.annotations.categories.ComplianceCategory;
import de.rub.nds.tlstest.framework.annotations.categories.HandshakeCategory;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;

import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertFalse;
import org.junit.jupiter.api.Test;

@RFC(number = 6066, section = "3. Server Name Indication")
@ClientTest
public class ServerNameIndication extends Tls12Test {

    public ConditionEvaluationResult sniActive() {
        if (context.getReceivedClientHelloMessage().getExtension(ServerNameIndicationExtensionMessage.class) != null) {
            return ConditionEvaluationResult.enabled("");
        }
        return ConditionEvaluationResult.disabled("SNI is disabled");
    }

    @Test
    @MethodCondition(method = "sniActive")
    @TestDescription("The ServerNameList MUST NOT contain more than one name of the same name_type.")
    @HandshakeCategory(SeverityLevel.LOW)
    @ComplianceCategory(SeverityLevel.MEDIUM)
    public void moreThanOneNameOfTheSameType() {
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
