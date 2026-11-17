/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.server.tls13.rfc8446;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.ExplicitValues;
import de.rub.nds.anvilcore.annotation.IncludeParameter;
import de.rub.nds.anvilcore.annotation.ManualConfig;
import de.rub.nds.anvilcore.annotation.ServerTest;
import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.teststate.AnvilTestCase;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SignatureAndHashAlgorithmsExtensionMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceConfigurationUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.TlsVersion;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.derivationParameter.SigAndHashDerivation;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Tag;

@ServerTest
public class SignatureAlgorithms extends Tls13Test {

    @TlsVersion(supported = {ProtocolVersion.TLS13, ProtocolVersion.DTLS13})
    @AnvilTest(id = "8446-kAJgkp7NBf")
    public void omitSignatureAlgorithmsExtension(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);
        c.setAddSignatureAndHashAlgorithmsExtension(false);

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                new SendAction(new ClientHelloMessage(c)), new ReceiveAction(new AlertMessage()));

        State state = runner.execute(workflowTrace, c);

        Validator.receivedFatalAlert(state, testCase, AlertDescription.MISSING_EXTENSION);
    }

    public List<DerivationParameter<Config, SignatureAndHashAlgorithm>> getLegacySigHashAlgoritms(
            DerivationScope scope) {
        List<DerivationParameter<Config, SignatureAndHashAlgorithm>> parameterValues =
                new LinkedList<>();
        List<SignatureAndHashAlgorithm> algos =
                SignatureAndHashAlgorithm.getImplemented().stream()
                        .filter(i -> !i.suitedForSigningTls13Messages())
                        .collect(Collectors.toList());
        algos.forEach(i -> parameterValues.add(new SigAndHashDerivation(i)));
        return parameterValues;
    }

    @AnvilTest(id = "8446-gKTTeCxk6m")
    @IncludeParameter("SIG_HASH_ALGORIHTM")
    @ManualConfig(identifiers = "SIG_HASH_ALGORIHTM")
    @ExplicitValues(
            affectedIdentifiers = "SIG_HASH_ALGORIHTM",
            methods = "getLegacySigHashAlgoritms")
    public void offerLegacySignatureAlgorithms(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);
        SignatureAndHashAlgorithm selectedSigHash =
                parameterCombination.getParameter(SigAndHashDerivation.class).getSelectedValue();

        List<SignatureAndHashAlgorithm> algos =
                SignatureAndHashAlgorithm.getImplemented().stream()
                        .filter(SignatureAndHashAlgorithm::suitedForSigningTls13Messages)
                        .collect(Collectors.toList());
        algos.add(0, selectedSigHash);

        c.setDefaultClientSupportedSignatureAndHashAlgorithms(algos);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);

        State state = runner.execute(workflowTrace, c);

        Validator.executedAsPlanned(state, testCase);

        CertificateVerifyMessage certVerifyMsg =
                state.getWorkflowTrace().getFirstReceivedMessage(CertificateVerifyMessage.class);
        assertNotNull(certVerifyMsg);
        SignatureAndHashAlgorithm sigHashAlg =
                SignatureAndHashAlgorithm.getSignatureAndHashAlgorithm(
                        certVerifyMsg.getSignatureHashAlgorithm().getValue());
        assertTrue(
                sigHashAlg.suitedForSigningTls13Messages(),
                "Invalid SignatureAndHashAlgorithm negotiated");
    }

    @AnvilTest(id = "8446-3WqNtgoV2Z")
    @IncludeParameter("SIG_HASH_ALGORIHTM")
    @ExplicitValues(
            affectedIdentifiers = "SIG_HASH_ALGORIHTM",
            methods = "getLegacySigHashAlgoritms")
    public void offerOnlyLegacySignatureAlgorithms(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                new SendAction(new ClientHelloMessage(c)), new ReceiveAction(new AlertMessage()));

        State state = runner.execute(workflowTrace, c);
        Validator.receivedFatalAlert(state, testCase);
    }

    @TlsVersion(supported = {ProtocolVersion.TLS13, ProtocolVersion.DTLS13})
    @AnvilTest(id = "8446-5YCxveMdpt")
    public void includeUnknownSignatureAndHashAlgorithm(
            AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);
        c.setAddSignatureAndHashAlgorithmsExtension(true);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        ClientHelloMessage clientHello =
                (ClientHelloMessage)
                        WorkflowTraceConfigurationUtil.getFirstStaticConfiguredSendMessage(
                                workflowTrace, HandshakeMessageType.CLIENT_HELLO);
        SignatureAndHashAlgorithmsExtensionMessage algorithmsExtension =
                clientHello.getExtension(SignatureAndHashAlgorithmsExtensionMessage.class);
        algorithmsExtension.setSignatureAndHashAlgorithms(
                Modifiable.insert(new byte[] {(byte) 0xfe, 0x44}, 0));

        State state = runner.execute(workflowTrace, c);
        Validator.executedAsPlanned(state, testCase);
    }

    @AnvilTest(id = "8446-0f06e5553f")
    @Tag("rfc8446-coverage")
    public void doesNotNegotiateObsoleteSignatureAlgorithms(
            AnvilTestCase testCase, WorkflowRunner runner) {
        Config config = getPreparedConfig(runner);

        // find all implemented algos that are obsolete in 1.3
        List<SignatureAndHashAlgorithm> obsoleteSignatureAndHashAlgorithms =
                SignatureAndHashAlgorithm.getImplemented().stream()
                        .filter(
                                de.rub.nds.tlstest.suite.tests.client.tls13.rfc8446
                                                .SignatureAlgorithms
                                        ::obsoleteAlgo)
                        .collect(Collectors.toList());

        // only offer these to the server
        config.setDefaultClientSupportedSignatureAndHashAlgorithms(
                obsoleteSignatureAndHashAlgorithms);
        testCase.addAdditionalResultInfo(
                "Anvil ClientHello offered only obsolete signature algorithms: "
                        + obsoleteSignatureAndHashAlgorithms.stream()
                                .map(algo -> String.format("%s (0x%04X)", algo, algo.getValue()))
                                .collect(Collectors.joining(",")));

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                new SendAction(new ClientHelloMessage(config)),
                new ReceiveAction(new AlertMessage()));
        State state = runner.execute(workflowTrace, config);

        String response =
                Validator.getMessagesOfLastReceive(state).stream()
                        .map(message -> message.toCompactString())
                        .collect(Collectors.joining(","));
        testCase.addAdditionalResultInfo(
                "Server response to Anvil's obsolete-only signature algorithms offer: "
                        + (response.isEmpty() ? "no TLS messages received" : response));

        // expect that we don't complete the handshake
        // RFC 8446 section 4.1.1: no common parameters requires handshake_failure
        // or insufficient_security. The obsolete_RESERVED rule itself names no alert.
        Validator.receivedFatalAlert(
                state,
                testCase,
                AlertDescription.HANDSHAKE_FAILURE,
                AlertDescription.INSUFFICIENT_SECURITY);
    }
}
