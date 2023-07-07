/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.client.tls12.rfc5246;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.NameType;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EncryptThenMacExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.GreaseExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PaddingExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.RenegotiationInfoExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerNameIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.sni.ServerNamePair;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.ClientFeatureExtractionResult;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.ClientTest;
import de.rub.nds.tlstest.framework.annotations.DynamicValueConstraints;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.ScopeExtensions;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.annotations.categories.AlertCategory;
import de.rub.nds.tlstest.framework.annotations.categories.ComplianceCategory;
import de.rub.nds.tlstest.framework.annotations.categories.HandshakeCategory;
import de.rub.nds.anvilcore.coffee4j.model.ModelFromScope;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.TlsModelType;
import de.rub.nds.tlstest.framework.model.TlsParameterType;
import de.rub.nds.tlstest.framework.model.derivationParameter.CompressionMethodDerivation;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;
import de.rub.nds.anvilcore.annotation.AnvilTest;

@ClientTest
public class ServerHello extends Tls12Test {

    @RFC(number = 5246, section = "7.4.1.4. Hello Extensions")
    @AnvilTest(
            description =
                    "If a client receives an extension type in ServerHello that it did "
                            + "not request in the associated ClientHello, it MUST abort the handshake with an "
                            + "unsupported_extension fatal alert.")
    @ModelFromScope(modelType = "CERTIFICATE")
    @HandshakeCategory(SeverityLevel.HIGH)
    @ComplianceCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.MEDIUM)
    public void sendAdditionalExtension(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        c.setAddRenegotiationInfoExtension(false);

        ClientHelloMessage clientHello = context.getReceivedClientHelloMessage();

        List<ExtensionMessage> receivedExtensions = clientHello.getExtensions();
        List<ExtensionType> types = new ArrayList<>();
        ExtensionMessage extensionMessage;

        for (ExtensionMessage i : receivedExtensions) {
            types.add(ExtensionType.getExtensionType(i.getExtensionType().getValue()));
        }

        if (!types.contains(ExtensionType.ENCRYPT_THEN_MAC)) {
            extensionMessage = new EncryptThenMacExtensionMessage();
        } else if (!types.contains(ExtensionType.SERVER_NAME_INDICATION)) {
            ServerNameIndicationExtensionMessage sni = new ServerNameIndicationExtensionMessage();
            ServerNamePair sniPair =
                    new ServerNamePair(NameType.HOST_NAME.getValue(), "localhost".getBytes());
            sni.setServerNameList(
                    new ArrayList<ServerNamePair>() {
                        {
                            add(sniPair);
                        }
                    });

            extensionMessage = sni;
        } else if (!types.contains(ExtensionType.RENEGOTIATION_INFO)) {
            RenegotiationInfoExtensionMessage rie = new RenegotiationInfoExtensionMessage();
            rie.setRenegotiationInfo(Modifiable.explicit("abc".getBytes()));
            extensionMessage = rie;
        } else if (!types.contains(ExtensionType.PADDING)) {
            PaddingExtensionMessage pem = new PaddingExtensionMessage();
            pem.setPaddingBytes(Modifiable.explicit(new byte[10]));
            extensionMessage = pem;
        } else {
            GreaseExtensionMessage greaseExtension =
                    new GreaseExtensionMessage(ExtensionType.GREASE_00, new byte[10]);
            // modify 0A 0A to E4 04
            greaseExtension.setExtensionBytes(
                    Modifiable.xor(new byte[] {(byte) 0xee, (byte) 0x0e}, 0));
            extensionMessage = greaseExtension;
        }

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsActions(new ReceiveAction(new AlertMessage()));

        ServerHelloMessage msg = workflowTrace.getFirstSendMessage(ServerHelloMessage.class);
        msg.addExtension(extensionMessage);

        runner.execute(workflowTrace, c)
                .validateFinal(
                        i -> {
                            Validator.receivedFatalAlert(i);

                            AlertMessage alertMsg =
                                    i.getWorkflowTrace()
                                            .getFirstReceivedMessage(AlertMessage.class);
                            Validator.testAlertDescription(
                                    i, AlertDescription.UNSUPPORTED_EXTENSION, alertMsg);
                        });
    }

    public boolean isUnproposedCompressionMethod(CompressionMethod compressionMethod) {
        List<CompressionMethod> proposedCompressionMethods =
                CompressionMethod.getCompressionMethods(
                        ((ClientFeatureExtractionResult) context.getFeatureExtractionResult())
                                .getReceivedClientHello()
                                .getCompressions()
                                .getValue());
        return !proposedCompressionMethods.contains(compressionMethod);
    }

    @AnvilTest(
            description =
                    "The single compression algorithm selected by the server from the "
                            + "list in ClientHello.compression_methods.")
    @RFC(number = 5246, section = "7.4.1.3.  Server Hello")
    @ScopeExtensions(TlsParameterType.COMPRESSION_METHOD)
    @DynamicValueConstraints(
            affectedTypes = TlsParameterType.COMPRESSION_METHOD,
            methods = "isUnproposedCompressionMethod")
    @ComplianceCategory(SeverityLevel.HIGH)
    @HandshakeCategory(SeverityLevel.HIGH)
    @AlertCategory(SeverityLevel.LOW)
    public void selectUnproposedCompressionMethod(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        CompressionMethod selectedCompressionMethod =
                derivationContainer
                        .getDerivation(CompressionMethodDerivation.class)
                        .getSelectedValue();

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));

        ServerHelloMessage serverHello =
                (ServerHelloMessage)
                        WorkflowTraceUtil.getFirstSendMessage(
                                HandshakeMessageType.SERVER_HELLO, workflowTrace);
        serverHello.setSelectedCompressionMethod(
                Modifiable.explicit(selectedCompressionMethod.getValue()));

        runner.execute(workflowTrace, c).validateFinal(Validator::receivedFatalAlert);
    }
}
