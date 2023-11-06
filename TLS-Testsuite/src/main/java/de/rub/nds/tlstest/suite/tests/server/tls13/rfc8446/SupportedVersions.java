/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.server.tls13.rfc8446;

import static org.junit.Assert.*;

import de.rub.nds.anvilcore.annotation.*;
import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SupportedVersionsExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.derivationParameter.CipherSuiteDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.ProtocolVersionDerivation;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@ServerTest
public class SupportedVersions extends Tls13Test {

    public ConditionEvaluationResult supportsTls12() {
        if (context.getFeatureExtractionResult()
                .getSupportedVersions()
                .contains(ProtocolVersion.TLS12)) {
            return ConditionEvaluationResult.enabled("");
        }
        return ConditionEvaluationResult.disabled("TLS 1.2 is not supported by the server.");
    }

    @AnvilTest(id = "8446-UwCnJTWbmd")
    @MethodCondition(method = "supportsTls12")
    @KeyExchange(supported = KeyExchangeType.ALL12)
    public void testVersionPreferrence(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = prepareConfig(context.getConfig().createConfig(), argumentAccessor, runner);

        c.setSupportedVersions(ProtocolVersion.TLS12, ProtocolVersion.TLS13);
        c.getDefaultClientSupportedCipherSuites()
                .addAll(
                        CipherSuite.getImplemented().stream()
                                .filter(CipherSuite::isTLS13)
                                .collect(Collectors.toList()));

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);

        runner.execute(workflowTrace, c).validateFinal(Validator::executedAsPlanned);
    }

    @AnvilTest(id = "8446-ZiLwhbnp3y")
    @MethodCondition(method = "supportsTls12")
    @KeyExchange(supported = KeyExchangeType.ALL12)
    public void omitSupportedVersionsExtension(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        c.setAddSupportedVersionsExtension(false);
        c.setHighestProtocolVersion(ProtocolVersion.TLS12);
        c.getDefaultClientSupportedCipherSuites()
                .addAll(
                        CipherSuite.getImplemented().stream()
                                .filter(CipherSuite::isTLS13)
                                .collect(Collectors.toList()));

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        runner.execute(workflowTrace, c).validateFinal(Validator::executedAsPlanned);
    }

    @AnvilTest(id = "8446-zCaAr5BmNR")
    @IncludeParameter("PROTOCOL_VERSION")
    @ExplicitValues(
            affectedIdentifiers = "PROTOCOL_VERSION",
            methods = "getUnsupportedProtocolVersions")
    @MethodCondition(method = "supportsTls12")
    @KeyExchange(supported = KeyExchangeType.ALL12)
    @Tag("new")
    public void supportedVersionsAbsentOnlyUnsupportedLegacyVersion(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        c.setAddSupportedVersionsExtension(false);
        c.setHighestProtocolVersion(ProtocolVersion.TLS12);
        byte[] chosenUnsupportedVersion =
                parameterCombination
                        .getParameter(ProtocolVersionDerivation.class)
                        .getSelectedValue();

        WorkflowTrace workflowTrace = new WorkflowTrace();
        ClientHelloMessage clientHello = new ClientHelloMessage(c);
        clientHello.setProtocolVersion(Modifiable.explicit(chosenUnsupportedVersion));
        workflowTrace.addTlsAction(new SendAction(clientHello));
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));
        runner.execute(workflowTrace, c)
                .validateFinal(
                        i -> {
                            Validator.receivedFatalAlert(i);
                            Validator.testAlertDescription(i, AlertDescription.PROTOCOL_VERSION);
                        });
    }

    public List<DerivationParameter<Config, byte[]>> getUnsupportedProtocolVersions(
            DerivationScope scope) {
        List<ProtocolVersion> consideredVersions = new LinkedList<>();
        consideredVersions.add(ProtocolVersion.SSL2);
        consideredVersions.add(ProtocolVersion.SSL3);
        consideredVersions.add(ProtocolVersion.TLS10);
        consideredVersions.add(ProtocolVersion.TLS11);
        consideredVersions.add(ProtocolVersion.TLS12);
        context.getFeatureExtractionResult()
                .getSupportedVersions()
                .forEach(version -> consideredVersions.remove(version));
        List<DerivationParameter<Config, byte[]>> parameterValues = new LinkedList<>();
        consideredVersions.forEach(
                version -> parameterValues.add(new ProtocolVersionDerivation(version.getValue())));
        return parameterValues;
    }

    @AnvilTest(id = "8446-ihyps8KzBF")
    @MethodCondition(method = "supportsTls12")
    @ManualConfig(identifiers = "CIPHER_SUITE")
    public void oldLegacyVersion(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        CipherSuite tls13CipherSuite =
                parameterCombination.getParameter(CipherSuiteDerivation.class).getSelectedValue();
        c.setDefaultClientSupportedCipherSuites(
                context.getFeatureExtractionResult().getCipherSuites().stream()
                        .filter(i -> !i.isTLS13())
                        .collect(Collectors.toList()));
        c.getDefaultClientSupportedCipherSuites().add(tls13CipherSuite);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        workflowTrace
                .getFirstSendMessage(ClientHelloMessage.class)
                .setProtocolVersion(Modifiable.explicit(new byte[] {3, 3}));

        runner.execute(workflowTrace, c)
                .validateFinal(
                        i -> {
                            Validator.executedAsPlanned(i);
                            assertEquals(
                                    "Wrong TLS Version selected",
                                    ProtocolVersion.TLS13,
                                    i.getState().getTlsContext().getSelectedProtocolVersion());
                        });
    }

    @AnvilTest(id = "8446-LoyBdjVUeE")
    public void unknownVersion(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);

        workflowTrace
                .getFirstSendMessage(ClientHelloMessage.class)
                .getExtension(SupportedVersionsExtensionMessage.class)
                .setSupportedVersions(Modifiable.explicit(new byte[] {0x05, 0x05, 0x03, 0x04}));

        runner.execute(workflowTrace, c).validateFinal(Validator::executedAsPlanned);
    }

    @AnvilTest(id = "8446-vdaMcxzYj2")
    @MethodCondition(method = "supportsTls12")
    @KeyExchange(supported = KeyExchangeType.ALL12)
    public void supportedVersionsWithoutTls13(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = prepareConfig(context.getConfig().createConfig(), argumentAccessor, runner);
        c.setAddSupportedVersionsExtension(true);
        c.setSupportedVersions(ProtocolVersion.TLS12);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);

        runner.execute(workflowTrace, c)
                .validateFinal(
                        i -> {
                            Validator.executedAsPlanned(i);

                            WorkflowTrace trace = i.getWorkflowTrace();
                            ServerHelloMessage msg =
                                    trace.getFirstReceivedMessage(ServerHelloMessage.class);
                            assertArrayEquals(
                                    "Invalid ProtocolVersion",
                                    new byte[] {0x03, 0x03},
                                    msg.getProtocolVersion().getValue());
                            assertNull(
                                    "Received supported_versions extension",
                                    msg.getExtension(SupportedVersionsExtensionMessage.class));
                        });
    }

    @AnvilTest(id = "8446-n5pojEqeaS")
    public void tls13Handshake(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);

        runner.execute(workflowTrace, c)
                .validateFinal(
                        i -> {
                            Validator.executedAsPlanned(i);
                            WorkflowTrace trace = i.getWorkflowTrace();
                            ServerHelloMessage serverHello =
                                    trace.getFirstReceivedMessage(ServerHelloMessage.class);
                            SupportedVersionsExtensionMessage supportedVersions =
                                    serverHello.getExtension(
                                            SupportedVersionsExtensionMessage.class);

                            assertNotNull(
                                    "No SupportedVersions extension received in ServerHello",
                                    supportedVersions);
                            assertArrayEquals(
                                    "legacy_version must be 0x0303",
                                    ProtocolVersion.TLS12.getValue(),
                                    serverHello.getProtocolVersion().getValue());
                            assertTrue(
                                    "SupportedVersions extension does not contain 0x0304",
                                    ProtocolVersion.getProtocolVersions(
                                                    supportedVersions
                                                            .getSupportedVersions()
                                                            .getValue())
                                            .contains(ProtocolVersion.TLS13));
                        });
    }

    @AnvilTest(id = "8446-2NRWKXH1nX")
    public void setLegacyVersionTo0304(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                new SendAction(new ClientHelloMessage(c)), new ReceiveAction(new AlertMessage()));

        ClientHelloMessage chm = workflowTrace.getFirstSendMessage(ClientHelloMessage.class);
        chm.setProtocolVersion(Modifiable.explicit(ProtocolVersion.TLS13.getValue()));
        chm.getExtension(SupportedVersionsExtensionMessage.class)
                .setSupportedVersions(Modifiable.explicit(ProtocolVersion.TLS12.getValue()));

        runner.execute(workflowTrace, c).validateFinal(Validator::receivedFatalAlert);
    }

    @AnvilTest(id = "8446-WKMbKXKLH1")
    public void setLegacyVersionTo0304WithoutSVExt(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        c.setAddSupportedVersionsExtension(false);

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                new SendAction(new ClientHelloMessage(c)), new ReceiveAction(new AlertMessage()));

        ClientHelloMessage chm = workflowTrace.getFirstSendMessage(ClientHelloMessage.class);
        chm.setProtocolVersion(Modifiable.explicit(ProtocolVersion.TLS13.getValue()));

        // note that we only offer TLS 1.3 cipher suites, the server is hence
        // forced to abort the handshake
        runner.execute(workflowTrace, c).validateFinal(Validator::receivedFatalAlert);
    }
}
