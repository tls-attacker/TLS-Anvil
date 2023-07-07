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

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.ExplicitValues;
import de.rub.nds.anvilcore.coffee4j.model.ModelFromScope;
import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SupportedVersionsExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.ClientTest;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.annotations.ManualConfig;
import de.rub.nds.tlstest.framework.annotations.MethodCondition;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.ScopeExtensions;
import de.rub.nds.tlstest.framework.annotations.TestDescription;
import de.rub.nds.tlstest.framework.annotations.categories.AlertCategory;
import de.rub.nds.tlstest.framework.annotations.categories.ComplianceCategory;
import de.rub.nds.tlstest.framework.annotations.categories.HandshakeCategory;
import de.rub.nds.tlstest.framework.annotations.categories.InteroperabilityCategory;
import de.rub.nds.tlstest.framework.annotations.categories.SecurityCategory;
import de.rub.nds.tlstest.framework.anvil.TlsAnvilConfig;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.TlsParameterType;
import de.rub.nds.tlstest.framework.model.derivationParameter.ProtocolVersionDerivation;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@RFC(number = 8446, section = "4.2.1 Supported Versions")
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

    public List<DerivationParameter<TlsAnvilConfig, byte[]>> getInvalidLegacyVersions(
            DerivationScope scope) {
        List<DerivationParameter<TlsAnvilConfig, byte[]>> parameterValues = new LinkedList<>();
        parameterValues.add(new ProtocolVersionDerivation(new byte[] {0x05, 0x05}));
        parameterValues.add(new ProtocolVersionDerivation(new byte[] {0x03, 0x04}));
        return parameterValues;
    }

    @AnvilTest(
            description =
                    "If this extension is present, clients MUST ignore the "
                            + "ServerHello.legacy_version value and MUST use "
                            + "only the \"supported_versions\" extension to determine the selected version.")
    @ModelFromScope(modelType = "CERTIFICATE")
    @ScopeExtensions(TlsParameterType.PROTOCOL_VERSION)
    @ManualConfig(TlsParameterType.PROTOCOL_VERSION)
    @ExplicitValues(affectedIdentifiers = "PROTOCOL_VERSION", methods = "getInvalidLegacyVersions")
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.HIGH)
    @SecurityCategory(SeverityLevel.MEDIUM)
    public void invalidLegacyVersion(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        byte[] chosenInvalidVersion =
                derivationContainer
                        .getDerivation(ProtocolVersionDerivation.class)
                        .getSelectedValue();

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        workflowTrace
                .getFirstSendMessage(ServerHelloMessage.class)
                .setProtocolVersion(Modifiable.explicit(chosenInvalidVersion));

        runner.execute(workflowTrace, c).validateFinal(Validator::executedAsPlanned);
    }

    @AnvilTest(
            description =
                    "If the \"supported_versions\" extension in the ServerHello "
                            + "contains a version not offered by the client or contains a version "
                            + "prior to TLS 1.3, the client MUST abort the "
                            + "handshake with an \"illegal_parameter\" alert.")
    @MethodCondition(method = "supportsTls12")
    @KeyExchange(supported = KeyExchangeType.ALL12)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.MEDIUM)
    @SecurityCategory(SeverityLevel.HIGH)
    public void selectOlderTlsVersionInTls12(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = prepareConfig(context.getConfig().createConfig(), argumentAccessor, runner);

        c.setAddSupportedVersionsExtension(true);
        c.setEnforceSettings(true);
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsActions(new ReceiveAction(new AlertMessage()));
        workflowTrace
                .getFirstSendMessage(ServerHelloMessage.class)
                .getExtension(SupportedVersionsExtensionMessage.class)
                .setSupportedVersions(Modifiable.explicit(new byte[] {0x03, 0x03}));

        runner.execute(workflowTrace, c)
                .validateFinal(
                        i -> {
                            Validator.receivedFatalAlert(i);

                            AlertMessage msg =
                                    i.getWorkflowTrace()
                                            .getFirstReceivedMessage(AlertMessage.class);
                            Validator.testAlertDescription(
                                    i, AlertDescription.ILLEGAL_PARAMETER, msg);
                        });
    }

    @AnvilTest(
            description =
                    "If the \"supported_versions\" extension in the ServerHello "
                            + "contains a version not offered by the client or contains a version "
                            + "prior to TLS 1.3, the client MUST abort the "
                            + "handshake with an \"illegal_parameter\" alert.")
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.MEDIUM)
    @SecurityCategory(SeverityLevel.HIGH)
    public void selectOlderTlsVersion(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        c.setEnforceSettings(true);
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsActions(new ReceiveAction(new AlertMessage()));
        workflowTrace
                .getFirstSendMessage(ServerHelloMessage.class)
                .getExtension(SupportedVersionsExtensionMessage.class)
                .setSupportedVersions(Modifiable.explicit(new byte[] {0x03, 0x03}));

        runner.execute(workflowTrace, c)
                .validateFinal(
                        i -> {
                            Validator.receivedFatalAlert(i);

                            AlertMessage msg =
                                    i.getWorkflowTrace()
                                            .getFirstReceivedMessage(AlertMessage.class);
                            Validator.testAlertDescription(
                                    i, AlertDescription.ILLEGAL_PARAMETER, msg);
                        });
    }

    /*@AnvilTest(description = "Implementations of this specification MUST send this " +
    "extension in the ClientHello containing all versions of TLS which they " +
    "are prepared to negotiate (for this specification, that means minimally " +
    "0x0304, but if previous versions of TLS are allowed to be " +
    "negotiated, they MUST be present as well).")*/
    @Test
    @TestDescription(
            "Implementations of this specification MUST send this extension in the "
                    + "ClientHello containing all versions of TLS which they are prepared to "
                    + "negotiate (for this specification, that means minimally 0x0304, but "
                    + "if previous versions of TLS are allowed to be negotiated, they MUST "
                    + "be present as well).")
    @InteroperabilityCategory(SeverityLevel.MEDIUM)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.MEDIUM)
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
        getUnsupportedTlsVersions(clientSupportedVersions)
                .forEach(
                        version ->
                                parameterValues.add(
                                        new ProtocolVersionDerivation(version.getValue())));
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

    @AnvilTest(
            description =
                    "The \"supported_versions\" extension is used by the client to indicate "
                            + "which versions of TLS it supports and by the server to indicate which "
                            + "version it is using.  The extension contains a list of supported "
                            + "versions in preference order, with the most preferred version first. [...]"
                            + "If the version chosen by the server is not supported by the client "
                            + "(or is not acceptable), the client MUST abort the handshake with a "
                            + "\"protocol_version\" alert.")
    @RFC(
            number = 8446,
            section = "4.2.1 Supported Versions and D.1. Negotiating with an Older Server")
    @ScopeExtensions(TlsParameterType.PROTOCOL_VERSION)
    @ExplicitValues(
            affectedIdentifiers = "PROTOCOL_VERSION",
            methods = "getUnsupportedProtocolVersions")
    @KeyExchange(supported = KeyExchangeType.ALL12)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.LOW)
    @ComplianceCategory(SeverityLevel.HIGH)
    @SecurityCategory(SeverityLevel.HIGH)
    @Tag("adjusted")
    public void negotiateUnproposedOldProtocolVersion(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = prepareConfig(context.getConfig().createConfig(), argumentAccessor, runner);
        byte[] oldProtocolVersion =
                derivationContainer
                        .getDerivation(ProtocolVersionDerivation.class)
                        .getSelectedValue();

        WorkflowTrace workflowTrace =
                runner.generateWorkflowTraceUntilSendingMessage(
                        WorkflowTraceType.HELLO, HandshakeMessageType.SERVER_HELLO);
        ServerHelloMessage serverHello = new ServerHelloMessage(config);
        serverHello.setProtocolVersion(Modifiable.explicit(oldProtocolVersion));
        workflowTrace.addTlsAction(new SendAction(serverHello));
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));

        runner.execute(workflowTrace, config)
                .validateFinal(
                        i -> {
                            Validator.receivedFatalAlert(i);
                            Validator.testAlertDescription(i, AlertDescription.PROTOCOL_VERSION);
                        });
    }

    @AnvilTest(
            description =
                    "The \"supported_versions\" extension is used by the client to indicate "
                            + "which versions of TLS it supports and by the server to indicate which "
                            + "version it is using.  The extension contains a list of supported "
                            + "versions in preference order, with the most preferred version first. [...]"
                            + "If the version chosen by the server is not supported by the client "
                            + "(or is not acceptable), the client MUST abort the handshake with a "
                            + "\"protocol_version\" alert.")
    @RFC(
            number = 8446,
            section = "4.2.1 Supported Versions and D.1. Negotiating with an Older Server")
    @ScopeExtensions(TlsParameterType.PROTOCOL_VERSION)
    @ExplicitValues(
            affectedIdentifiers = "PROTOCOL_VERSION",
            methods = "getUndefinedProtocolVersions")
    @KeyExchange(supported = KeyExchangeType.ALL12)
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.LOW)
    @ComplianceCategory(SeverityLevel.HIGH)
    @SecurityCategory(SeverityLevel.HIGH)
    @Tag("new")
    public void legacyNegotiateUndefinedProtocolVersion(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config config = prepareConfig(context.getConfig().createConfig(), argumentAccessor, runner);
        byte[] oldProtocolVersion =
                derivationContainer
                        .getDerivation(ProtocolVersionDerivation.class)
                        .getSelectedValue();

        WorkflowTrace workflowTrace =
                runner.generateWorkflowTraceUntilSendingMessage(
                        WorkflowTraceType.HELLO, HandshakeMessageType.SERVER_HELLO);
        ServerHelloMessage serverHello = new ServerHelloMessage(config);
        serverHello.setProtocolVersion(Modifiable.explicit(oldProtocolVersion));
        workflowTrace.addTlsAction(new SendAction(serverHello));
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));

        runner.execute(workflowTrace, config).validateFinal(Validator::receivedFatalAlert);
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
