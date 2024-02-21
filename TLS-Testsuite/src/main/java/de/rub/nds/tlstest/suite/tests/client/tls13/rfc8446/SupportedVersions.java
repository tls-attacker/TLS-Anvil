/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.client.tls13.rfc8446;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import de.rub.nds.anvilcore.annotation.*;
import de.rub.nds.anvilcore.coffee4j.model.ModelFromScope;
import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.teststate.AnvilTestCase;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SupportedVersionsExtensionMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.derivationParameter.ProtocolVersionDerivation;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;

@ClientTest
public class SupportedVersions extends Tls13Test {

    public ConditionEvaluationResult supportsTls12() {
        if (context.getFeatureExtractionResult()
                .getSupportedVersions()
                .contains(ProtocolVersion.TLS12)) {
            return ConditionEvaluationResult.enabled("");
        }
        return ConditionEvaluationResult.disabled("TLS 1.2 is not supported by the server.");
    }

    public List<DerivationParameter<Config, byte[]>> getInvalidLegacyVersions(
            DerivationScope scope) {
        List<DerivationParameter<Config, byte[]>> parameterValues = new LinkedList<>();
        parameterValues.add(new ProtocolVersionDerivation(new byte[] {0x05, 0x05}));
        parameterValues.add(new ProtocolVersionDerivation(new byte[] {0x03, 0x04}));
        return parameterValues;
    }

    @AnvilTest(id = "8446-oysw9PbeiT")
    @ModelFromScope(modelType = "CERTIFICATE")
    @IncludeParameter("PROTOCOL_VERSION")
    @ManualConfig(identifiers = "PROTOCOL_VERSION")
    @ExplicitValues(affectedIdentifiers = "PROTOCOL_VERSION", methods = "getInvalidLegacyVersions")
    public void invalidLegacyVersion(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);
        byte[] chosenInvalidVersion =
                parameterCombination
                        .getParameter(ProtocolVersionDerivation.class)
                        .getSelectedValue();

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        workflowTrace
                .getFirstSendMessage(ServerHelloMessage.class)
                .setProtocolVersion(Modifiable.explicit(chosenInvalidVersion));

        State state = runner.execute(workflowTrace, c);
        Validator.executedAsPlanned(state, testCase);
    }

    @AnvilTest(id = "8446-w9k9gMLaeU")
    @MethodCondition(method = "supportsTls12")
    @KeyExchange(supported = KeyExchangeType.ALL12)
    public void selectOlderTlsVersionInTls12(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = prepareConfig(context.getConfig().createConfig(), runner);

        c.setAddSupportedVersionsExtension(true);
        c.setEnforceSettings(true);
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsActions(new ReceiveAction(new AlertMessage()));
        workflowTrace
                .getFirstSendMessage(ServerHelloMessage.class)
                .getExtension(SupportedVersionsExtensionMessage.class)
                .setSupportedVersions(Modifiable.explicit(new byte[] {0x03, 0x03}));

        State state = runner.execute(workflowTrace, c);

        Validator.receivedFatalAlert(state, testCase);
        AlertMessage msg = state.getWorkflowTrace().getFirstReceivedMessage(AlertMessage.class);
        Validator.testAlertDescription(state, testCase, AlertDescription.ILLEGAL_PARAMETER, msg);
    }

    @AnvilTest(id = "8446-YDjQAqZ2LM")
    public void selectOlderTlsVersion(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);
        c.setEnforceSettings(true);
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsActions(new ReceiveAction(new AlertMessage()));
        workflowTrace
                .getFirstSendMessage(ServerHelloMessage.class)
                .getExtension(SupportedVersionsExtensionMessage.class)
                .setSupportedVersions(Modifiable.explicit(new byte[] {0x03, 0x03}));

        State state = runner.execute(workflowTrace, c);

        Validator.receivedFatalAlert(state, testCase);
        AlertMessage msg = state.getWorkflowTrace().getFirstReceivedMessage(AlertMessage.class);
        Validator.testAlertDescription(state, testCase, AlertDescription.ILLEGAL_PARAMETER, msg);
    }

    @NonCombinatorialAnvilTest(id = "8446-o5uxfywWFS")
    public void supportedVersionContainsTls13() {
        SupportedVersionsExtensionMessage ext =
                context.getReceivedClientHelloMessage()
                        .getExtension(SupportedVersionsExtensionMessage.class);
        assertNotNull("CH Does not contain supported_versions extension", ext);

        List<ProtocolVersion> versions =
                ProtocolVersion.getProtocolVersions(ext.getSupportedVersions().getValue());
        assertTrue(
                "supported_versions does not contain TLS 1.3",
                versions.contains(ProtocolVersion.TLS13));
    }

    public List<DerivationParameter> getUnsupportedProtocolVersions(DerivationScope scope) {
        SupportedVersionsExtensionMessage clientSupportedVersions =
                TestContext.getInstance()
                        .getReceivedClientHelloMessage()
                        .getExtension(SupportedVersionsExtensionMessage.class);
        List<DerivationParameter> parameterValues = new LinkedList<>();
        if (clientSupportedVersions != null) {
            getUnsupportedTlsVersions(clientSupportedVersions)
                    .forEach(
                            version ->
                                    parameterValues.add(
                                            new ProtocolVersionDerivation(version.getValue())));
        }
        return parameterValues;
    }

    private List<ProtocolVersion> getUnsupportedTlsVersions(
            SupportedVersionsExtensionMessage clientSupportedVersions) {
        // negotiating SSL3 is a separate test
        List<ProtocolVersion> versions = new LinkedList<>();
        versions.add(ProtocolVersion.TLS10);
        versions.add(ProtocolVersion.TLS11);
        versions.add(ProtocolVersion.TLS12);

        byte[] supportedVersions = clientSupportedVersions.getSupportedVersions().getValue();
        int versionLength = clientSupportedVersions.getSupportedVersionsLength().getValue();

        for (int i = 0; i < versionLength; i += 2) {
            ProtocolVersion version =
                    ProtocolVersion.getProtocolVersion(
                            Arrays.copyOfRange(supportedVersions, i, i + 2));
            versions.remove(version);
        }

        return versions;
    }

    @AnvilTest(id = "8446-cck1BzgJ1h")
    @IncludeParameter("PROTOCOL_VERSION")
    @ExplicitValues(
            affectedIdentifiers = "PROTOCOL_VERSION",
            methods = "getUnsupportedProtocolVersions")
    @KeyExchange(supported = KeyExchangeType.ALL12)
    @Tag("adjusted")
    public void negotiateUnproposedOldProtocolVersion(
            AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = prepareConfig(context.getConfig().createConfig(), runner);
        byte[] oldProtocolVersion =
                parameterCombination
                        .getParameter(ProtocolVersionDerivation.class)
                        .getSelectedValue();

        WorkflowTrace workflowTrace =
                runner.generateWorkflowTraceUntilSendingMessage(
                        WorkflowTraceType.HELLO, HandshakeMessageType.SERVER_HELLO);
        ServerHelloMessage serverHello = new ServerHelloMessage(config);
        serverHello.setProtocolVersion(Modifiable.explicit(oldProtocolVersion));
        workflowTrace.addTlsAction(new SendAction(serverHello));
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));

        State state = runner.execute(workflowTrace, config);

        Validator.receivedFatalAlert(state, testCase);
        Validator.testAlertDescription(state, testCase, AlertDescription.PROTOCOL_VERSION);
    }

    @AnvilTest(id = "8446-eNP4DYhWjk")
    @IncludeParameter("PROTOCOL_VERSION")
    @ExplicitValues(
            affectedIdentifiers = "PROTOCOL_VERSION",
            methods = "getUndefinedProtocolVersions")
    @KeyExchange(supported = KeyExchangeType.ALL12)
    @Tag("new")
    public void legacyNegotiateUndefinedProtocolVersion(
            AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = prepareConfig(context.getConfig().createConfig(), runner);
        byte[] oldProtocolVersion =
                parameterCombination
                        .getParameter(ProtocolVersionDerivation.class)
                        .getSelectedValue();

        WorkflowTrace workflowTrace =
                runner.generateWorkflowTraceUntilSendingMessage(
                        WorkflowTraceType.HELLO, HandshakeMessageType.SERVER_HELLO);
        ServerHelloMessage serverHello = new ServerHelloMessage(config);
        serverHello.setProtocolVersion(Modifiable.explicit(oldProtocolVersion));
        workflowTrace.addTlsAction(new SendAction(serverHello));
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));

        State state = runner.execute(workflowTrace, config);
        Validator.receivedFatalAlert(state, testCase);
    }

    public List<DerivationParameter> getUndefinedProtocolVersions(DerivationScope scope) {
        List<DerivationParameter> parameterValues = new LinkedList<>();
        // 03 04 is a separate test
        parameterValues.add(new ProtocolVersionDerivation(new byte[] {0x03, 0x05}));
        parameterValues.add(new ProtocolVersionDerivation(new byte[] {0x04, 0x04}));
        parameterValues.add(new ProtocolVersionDerivation(new byte[] {0x05, 0x03}));
        parameterValues.add(new ProtocolVersionDerivation(new byte[] {(byte) 0x99, 0x04}));
        return parameterValues;
    }
}
