/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.client.tls12.rfc5246;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.NameType;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EncryptThenMacExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PaddingExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.RenegotiationInfoExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerNameIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.sni.ServerNamePair;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.ClientTest;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;

import java.util.ArrayList;
import java.util.List;


@ClientTest
public class ServerHello extends Tls12Test {

    @RFC(number = 5246, section = "7.4.1.4. Hello Extensions")
    @TlsTest(description = "If a client receives an extension type in ServerHello that it did "+
            "not request in the associated ClientHello, it MUST abort the handshake with an " +
            "unsupported_extension fatal alert.")
    public void sendAdditionalExtension(WorkflowRunner runner) {
        ClientHelloMessage clientHello = context.getReceivedClientHelloMessage();
        runner.replaceSelectedCiphersuite = true;

        List<ExtensionMessage> receivedExtensions = clientHello.getExtensions();
        List<ExtensionType> types = new ArrayList<>();
        ExtensionMessage extensionMessage;

        for (ExtensionMessage i : receivedExtensions) {
            types.add(ExtensionType.getExtensionType(i.getExtensionType().getValue()));
        }

        if (!types.contains(ExtensionType.ENCRYPT_THEN_MAC)) {
            extensionMessage = new EncryptThenMacExtensionMessage();
        }
        else if (!types.contains(ExtensionType.SERVER_NAME_INDICATION)) {
            ServerNameIndicationExtensionMessage sni = new ServerNameIndicationExtensionMessage();
            ServerNamePair sniPair = new ServerNamePair();
            sniPair.setServerName(Modifiable.explicit("localhost".getBytes()));
            sniPair.setServerNameType(Modifiable.explicit(NameType.HOST_NAME.getValue()));
            sni.setServerNameList(new ArrayList<ServerNamePair>(){{add(sniPair);}});

            extensionMessage = sni;
        }
        else if (!types.contains(ExtensionType.RENEGOTIATION_INFO)) {
            RenegotiationInfoExtensionMessage rie = new RenegotiationInfoExtensionMessage();
            rie.setRenegotiationInfo(Modifiable.explicit("abc".getBytes()));
            extensionMessage = rie;
        }
        else if (!types.contains(ExtensionType.PADDING)) {
            PaddingExtensionMessage pem = new PaddingExtensionMessage();
            pem.setExtensionBytes(Modifiable.explicit(new byte[10]));
            extensionMessage = pem;
        }
        else {
            throw new AssertionError("Every extension was sent by the client...");
        }

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsActions(
                new ReceiveAction(new AlertMessage())
        );

        runner.setStateModifier(i -> {
            ServerHelloMessage msg = i.getWorkflowTrace().getFirstSendMessage(ServerHelloMessage.class);
            msg.addExtension(extensionMessage);
            return null;
        });

        runner.execute(workflowTrace).validateFinal(i -> {
            Validator.receivedFatalAlert(i);

            AlertMessage msg = i.getWorkflowTrace().getFirstReceivedMessage(AlertMessage.class);
            Validator.testAlertDescription(i, AlertDescription.UNSUPPORTED_EXTENSION, msg);
        });

    }
}
