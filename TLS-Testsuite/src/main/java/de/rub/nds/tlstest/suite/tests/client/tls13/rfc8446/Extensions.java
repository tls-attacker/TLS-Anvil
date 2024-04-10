/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.client.tls13.rfc8446;

import de.rub.nds.anvilcore.annotation.*;
import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.teststate.AnvilTestCase;
import de.rub.nds.anvilcore.teststate.TestResult;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.MaxFragmentLength;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.EncryptedExtensionsMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.AlpnExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.HeartbeatExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.MaxFragmentLengthExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerNameIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.derivationParameter.ExtensionDerivation;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;

@ClientTest
public class Extensions extends Tls13Test {

    public List<DerivationParameter<Config, ExtensionType>> getUnrequestedExtensions(
            DerivationScope scope) {
        List<DerivationParameter<Config, ExtensionType>> parameterValues = new LinkedList<>();
        List<ExtensionType> extensions = new LinkedList<>();
        extensions.add(ExtensionType.SERVER_NAME_INDICATION);
        extensions.add(ExtensionType.MAX_FRAGMENT_LENGTH);
        extensions.add(ExtensionType.ALPN);
        List<ExtensionType> clientExtensions =
                context.getReceivedClientHelloMessage().getExtensions().stream()
                        .map(i -> ExtensionType.getExtensionType(i.getExtensionType().getValue()))
                        .collect(Collectors.toList());
        extensions.removeAll(clientExtensions);

        for (ExtensionType unrequestedType : extensions) {
            parameterValues.add(new ExtensionDerivation(unrequestedType));
        }

        return parameterValues;
    }

    @AnvilTest(id = "8446-guYpWN18yk")
    @IncludeParameter("EXTENSION")
    @ManualConfig(identifiers = "EXTENSION")
    @ExplicitValues(affectedIdentifiers = "EXTENSION", methods = "getUnrequestedExtensions")
    public void sendAdditionalExtension(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);
        ExtensionType selectedExtension =
                parameterCombination.getParameter(ExtensionDerivation.class).getSelectedValue();

        List<ExtensionType> extensions = new ArrayList<>(Arrays.asList(ExtensionType.values()));
        List<ExtensionType> clientExtensions =
                context.getReceivedClientHelloMessage().getExtensions().stream()
                        .map(i -> ExtensionType.getExtensionType(i.getExtensionType().getValue()))
                        .collect(Collectors.toList());
        extensions.removeAll(clientExtensions);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsActions(new ReceiveAction(new AlertMessage()));

        if (selectedExtension == ExtensionType.MAX_FRAGMENT_LENGTH) {
            MaxFragmentLengthExtensionMessage ext = new MaxFragmentLengthExtensionMessage();
            ext.setMaxFragmentLength(
                    Modifiable.explicit(new byte[] {MaxFragmentLength.TWO_11.getValue()}));

            workflowTrace.getFirstSendMessage(EncryptedExtensionsMessage.class).addExtension(ext);
        } else if (selectedExtension == ExtensionType.ALPN) {
            c.setDefaultProposedAlpnProtocols(
                    "http/1.1",
                    "spdy/1",
                    "spdy/2",
                    "spdy/3",
                    "stun.turn",
                    "stun.nat-discovery",
                    "h2",
                    "h2c",
                    "webrtc",
                    "c-webrtc",
                    "ftp",
                    "imap",
                    "pop3",
                    "managesieve");
            AlpnExtensionMessage ext = new AlpnExtensionMessage();
            workflowTrace.getFirstSendMessage(EncryptedExtensionsMessage.class).addExtension(ext);
        } else if (selectedExtension == ExtensionType.SERVER_NAME_INDICATION) {
            ServerNameIndicationExtensionMessage ext = new ServerNameIndicationExtensionMessage();
            workflowTrace.getFirstSendMessage(EncryptedExtensionsMessage.class).addExtension(ext);
        } else {
            LOGGER.warn("ClientHello already contains every extension");
            throw new AssertionError("ClientHello already contains every extension");
        }

        State state = runner.execute(workflowTrace, c);

        Validator.receivedFatalAlert(state, testCase);
        AlertMessage msg = state.getWorkflowTrace().getFirstReceivedMessage(AlertMessage.class);
        Validator.testAlertDescription(
                state, testCase, AlertDescription.UNSUPPORTED_EXTENSION, msg);
    }

    @AnvilTest(id = "8446-6dvAUhLdUW")
    public void sendHeartBeatExtensionInSH(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsActions(new ReceiveAction(new AlertMessage()));

        workflowTrace
                .getFirstSendMessage(ServerHelloMessage.class)
                .addExtension(new HeartbeatExtensionMessage());

        State state = runner.execute(workflowTrace, c);

        WorkflowTrace trace = state.getWorkflowTrace();
        Validator.receivedFatalAlert(state, testCase);

        AlertMessage msg = trace.getFirstReceivedMessage(AlertMessage.class);
        Validator.testAlertDescription(state, testCase, AlertDescription.ILLEGAL_PARAMETER, msg);
        if (msg != null
                && msg.getDescription().getValue()
                        == AlertDescription.UNSUPPORTED_EXTENSION.getValue()
                && !context.getReceivedClientHelloMessage()
                        .containsExtension(ExtensionType.HEARTBEAT)
                && testCase.getTestResult() == TestResult.CONCEPTUALLY_SUCCEEDED) {
            testCase.setTestResult(TestResult.STRICTLY_SUCCEEDED);
            testCase.addAdditionalResultInfo(
                    "Description is acceptable as Heartbeat was not proposed by client");
        }
    }
}
