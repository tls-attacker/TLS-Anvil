/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.client.tls12.rfc8701;

import static org.junit.Assert.assertTrue;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.ClientTest;
import de.rub.nds.anvilcore.annotation.ExcludeParameter;
import de.rub.nds.anvilcore.annotation.IncludeParameter;
import de.rub.nds.anvilcore.teststate.AnvilTestCase;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.GreaseExtensionMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceConfigurationUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.derivationParameter.*;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;

@ClientTest
public class ServerInitiatedExtensionPoints extends Tls12Test {

    @AnvilTest(id = "8701-1yNET6C4bb")
    @IncludeParameter("GREASE_PROTOCOL_VERSION")
    public void selectGreaseVersion(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsActions(new ReceiveAction(new AlertMessage()));

        ProtocolVersion greaseVersion =
                parameterCombination
                        .getParameter(GreaseProtocolVersionDerivation.class)
                        .getSelectedValue();
        ServerHelloMessage sh =
                (ServerHelloMessage)
                        WorkflowTraceConfigurationUtil.getFirstStaticConfiguredSendMessage(
                                workflowTrace, HandshakeMessageType.SERVER_HELLO);
        sh.setProtocolVersion(Modifiable.explicit(greaseVersion.getValue()));

        State state = runner.execute(workflowTrace, c);

        if (context.getFeatureExtractionResult().getResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_3)
                == TestResults.TRUE) {
            // In TLS 1.3, alerts are not mandatory - at this point no version
            // has been negotiated
            assertTrue("Socket has not been closed", Validator.socketClosed(state));
        } else {
            Validator.receivedFatalAlert(state, testCase);
        }
    }

    @AnvilTest(id = "8701-tEzdghyrj5")
    @ExcludeParameter("CIPHER_SUITE")
    @IncludeParameter("GREASE_CIPHERSUITE")
    public void selectGreaseCipherSuite(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);
        CipherSuite greaseCipher =
                parameterCombination
                        .getParameter(GreaseCipherSuiteDerivation.class)
                        .getSelectedValue();

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsActions(new ReceiveAction(new AlertMessage()));

        ServerHelloMessage sh =
                (ServerHelloMessage)
                        WorkflowTraceConfigurationUtil.getFirstStaticConfiguredSendMessage(
                                workflowTrace, HandshakeMessageType.SERVER_HELLO);
        sh.setSelectedCipherSuite(Modifiable.explicit(greaseCipher.getByteValue()));

        State state = runner.execute(workflowTrace, c);
        Validator.receivedFatalAlert(state, testCase);
    }

    @AnvilTest(id = "8701-KSVZP6dF7j")
    @IncludeParameter("GREASE_EXTENSION")
    public void sendServerHelloGreaseExtension(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);
        ExtensionType greaseExtension =
                parameterCombination
                        .getParameter(GreaseExtensionDerivation.class)
                        .getSelectedValue();

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsActions(new ReceiveAction(new AlertMessage()));

        ServerHelloMessage sh =
                (ServerHelloMessage)
                        WorkflowTraceConfigurationUtil.getFirstStaticConfiguredSendMessage(
                                workflowTrace, HandshakeMessageType.SERVER_HELLO);
        sh.addExtension(new GreaseExtensionMessage(greaseExtension, 25));

        State state = runner.execute(workflowTrace, c);
        Validator.receivedFatalAlert(state, testCase);
    }

    @AnvilTest(id = "8701-Dct8jKkrvf")
    @KeyExchange(supported = KeyExchangeType.ECDH, requiresServerKeyExchMsg = true)
    @ExcludeParameter("NAMED_GROUP")
    @IncludeParameter("GREASE_NAMED_GROUP")
    public void selectGreaseNamedGroup(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsActions(new ReceiveAction(new AlertMessage()));

        NamedGroup greaseGroup =
                parameterCombination
                        .getParameter(GreaseNamedGroupDerivation.class)
                        .getSelectedValue();
        ECDHEServerKeyExchangeMessage skx =
                (ECDHEServerKeyExchangeMessage)
                        WorkflowTraceConfigurationUtil.getFirstStaticConfiguredSendMessage(
                                workflowTrace, HandshakeMessageType.SERVER_KEY_EXCHANGE);
        skx.setNamedGroup(Modifiable.explicit(greaseGroup.getValue()));

        State state = runner.execute(workflowTrace, c);
        Validator.receivedFatalAlert(state, testCase);
    }

    @AnvilTest(id = "8701-1YAGJouHo8")
    @KeyExchange(supported = KeyExchangeType.ALL12, requiresServerKeyExchMsg = true)
    @IncludeParameter("GREASE_SIG_HASH")
    public void selectGreaseSignatureAlgorithm(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsActions(new ReceiveAction(new AlertMessage()));

        SignatureAndHashAlgorithm greaseSigHash =
                parameterCombination.getParameter(GreaseSigHashDerivation.class).getSelectedValue();
        ServerKeyExchangeMessage skx =
                (ServerKeyExchangeMessage)
                        WorkflowTraceConfigurationUtil.getFirstStaticConfiguredSendMessage(
                                workflowTrace, HandshakeMessageType.SERVER_KEY_EXCHANGE);
        skx.setSignatureAndHashAlgorithm(Modifiable.explicit(greaseSigHash.getByteValue()));

        State state = runner.execute(workflowTrace, c);
        Validator.receivedFatalAlert(state, testCase);
    }
}
