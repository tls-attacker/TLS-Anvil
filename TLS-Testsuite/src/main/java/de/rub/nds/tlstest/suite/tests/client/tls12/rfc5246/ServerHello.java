/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.client.tls12.rfc5246;

import de.rub.nds.anvilcore.annotation.*;
import de.rub.nds.anvilcore.coffee4j.model.ModelFromScope;
import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.teststate.AnvilTestCase;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.*;
import de.rub.nds.tlsattacker.core.protocol.message.extension.sni.ServerNamePair;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceConfigurationUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.ClientFeatureExtractionResult;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.derivationParameter.CompressionMethodDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.ExtensionDerivation;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

@ClientTest
public class ServerHello extends Tls12Test {

    public List<DerivationParameter<Config, ExtensionType>> getUnrequestedExtensions(
            DerivationScope scope) {
        List<DerivationParameter<Config, ExtensionType>> parameterValues = new LinkedList<>();
        List<ExtensionType> extensions = new LinkedList<>();
        extensions.add(ExtensionType.ENCRYPT_THEN_MAC);
        extensions.add(ExtensionType.SERVER_NAME_INDICATION);
        extensions.add(ExtensionType.RENEGOTIATION_INFO);
        extensions.add(ExtensionType.PADDING);

        List<ExtensionType> clientExtensions =
                context.getReceivedClientHelloMessage().getExtensions().stream()
                        .map(i -> ExtensionType.getExtensionType(i.getExtensionType().getValue()))
                        .toList();
        extensions.removeAll(clientExtensions);
        if (extensions.isEmpty()) {
            extensions.add(ExtensionType.GREASE_00);
        }
        for (ExtensionType unrequestedType : extensions) {
            parameterValues.add(new ExtensionDerivation(unrequestedType));
        }
        return parameterValues;
    }

    @AnvilTest(id = "5246-YnrTYxwh4n")
    @ModelFromScope(modelType = "CERTIFICATE")
    @IncludeParameter("EXTENSION")
    @ManualConfig(identifiers = "EXTENSION")
    @ExplicitValues(affectedIdentifiers = "EXTENSION", methods = "getUnrequestedExtensions")
    public void sendAdditionalExtension(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);
        c.setAddRenegotiationInfoExtension(false);

        ExtensionType type =
                parameterCombination.getParameter(ExtensionDerivation.class).getSelectedValue();
        ExtensionMessage extensionMessage;

        if (type == ExtensionType.ENCRYPT_THEN_MAC) {
            extensionMessage = new EncryptThenMacExtensionMessage();
        } else if (type == ExtensionType.SERVER_NAME_INDICATION) {
            ServerNameIndicationExtensionMessage sni = new ServerNameIndicationExtensionMessage();
            ServerNamePair sniPair =
                    new ServerNamePair(SniType.HOST_NAME.getValue(), "localhost".getBytes());
            sni.setServerNameList(
                    new ArrayList<>() {
                        {
                            add(sniPair);
                        }
                    });

            extensionMessage = sni;
        } else if (type == ExtensionType.RENEGOTIATION_INFO) {
            RenegotiationInfoExtensionMessage rie = new RenegotiationInfoExtensionMessage();
            rie.setRenegotiationInfo(Modifiable.explicit("abc".getBytes()));
            extensionMessage = rie;
        } else if (type == ExtensionType.PADDING) {
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

        ServerHelloMessage msg =
                (ServerHelloMessage)
                        WorkflowTraceConfigurationUtil.getFirstStaticConfiguredSendMessage(
                                workflowTrace, HandshakeMessageType.SERVER_HELLO);
        msg.addExtension(extensionMessage);

        State state = runner.execute(workflowTrace, c);
        Validator.receivedFatalAlert(state, testCase);

        AlertMessage alertMsg =
                state.getWorkflowTrace().getFirstReceivedMessage(AlertMessage.class);
        Validator.testAlertDescription(
                state, testCase, AlertDescription.UNSUPPORTED_EXTENSION, alertMsg);
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

    @AnvilTest(id = "5246-UXM2CG5DPA")
    @IncludeParameter("COMPRESSION_METHOD")
    @DynamicValueConstraints(
            affectedIdentifiers = "COMPRESSION_METHOD",
            methods = "isUnproposedCompressionMethod")
    public void selectUnproposedCompressionMethod(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);
        CompressionMethod selectedCompressionMethod =
                parameterCombination
                        .getParameter(CompressionMethodDerivation.class)
                        .getSelectedValue();

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));

        ServerHelloMessage serverHello =
                (ServerHelloMessage)
                        WorkflowTraceConfigurationUtil.getFirstStaticConfiguredSendMessage(
                                workflowTrace, HandshakeMessageType.SERVER_HELLO);
        serverHello.setSelectedCompressionMethod(
                Modifiable.explicit(selectedCompressionMethod.getValue()));

        State state = runner.execute(workflowTrace, c);
        Validator.receivedFatalAlert(state, testCase);
    }
}
