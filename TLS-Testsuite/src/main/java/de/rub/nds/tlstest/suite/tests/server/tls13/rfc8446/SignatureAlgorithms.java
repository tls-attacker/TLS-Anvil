/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.server.tls13.rfc8446;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import de.rub.nds.anvilcore.annotation.*;
import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SignatureAndHashAlgorithmsExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.derivationParameter.SigAndHashDerivation;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@ServerTest
public class SignatureAlgorithms extends Tls13Test {

    @AnvilTest(id = "8446-kAJgkp7NBf")
    public void omitSignatureAlgorithmsExtension(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        c.setAddSignatureAndHashAlgorithmsExtension(false);

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                new SendAction(new ClientHelloMessage(c)), new ReceiveAction(new AlertMessage()));

        runner.execute(workflowTrace, c)
                .validateFinal(
                        i -> {
                            Validator.receivedFatalAlert(i);

                            AlertMessage msg =
                                    i.getWorkflowTrace()
                                            .getFirstReceivedMessage(AlertMessage.class);
                            Validator.testAlertDescription(
                                    i, AlertDescription.MISSING_EXTENSION, msg);
                        });
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
    public void offerLegacySignatureAlgorithms(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        SignatureAndHashAlgorithm selectedSigHash =
                parameterCombination.getParameter(SigAndHashDerivation.class).getSelectedValue();

        List<SignatureAndHashAlgorithm> algos =
                SignatureAndHashAlgorithm.getImplemented().stream()
                        .filter(SignatureAndHashAlgorithm::suitedForSigningTls13Messages)
                        .collect(Collectors.toList());
        algos.add(0, selectedSigHash);

        c.setDefaultClientSupportedSignatureAndHashAlgorithms(algos);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);

        runner.execute(workflowTrace, c)
                .validateFinal(
                        i -> {
                            Validator.executedAsPlanned(i);

                            CertificateVerifyMessage certVerifyMsg =
                                    i.getWorkflowTrace()
                                            .getFirstReceivedMessage(
                                                    CertificateVerifyMessage.class);
                            assertNotNull(certVerifyMsg);
                            SignatureAndHashAlgorithm sigHashAlg =
                                    SignatureAndHashAlgorithm.getSignatureAndHashAlgorithm(
                                            certVerifyMsg.getSignatureHashAlgorithm().getValue());
                            assertTrue(
                                    "Invalid SignatureAndHashAlgorithm negotiated",
                                    sigHashAlg.suitedForSigningTls13Messages());
                        });
    }

    @AnvilTest(id = "8446-3WqNtgoV2Z")
    @IncludeParameter("SIG_HASH_ALGORIHTM")
    @ExplicitValues(
            affectedIdentifiers = "SIG_HASH_ALGORIHTM",
            methods = "getLegacySigHashAlgoritms")
    public void offerOnlyLegacySignatureAlgorithms(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        WorkflowTrace workflowTrace = new WorkflowTrace();
        workflowTrace.addTlsActions(
                new SendAction(new ClientHelloMessage(c)), new ReceiveAction(new AlertMessage()));

        runner.execute(workflowTrace, c).validateFinal(Validator::receivedFatalAlert);
    }

    @AnvilTest(id = "8446-5YCxveMdpt")
    public void includeUnknownSignatureAndHashAlgorithm(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        c.setAddSignatureAndHashAlgorithmsExtension(true);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        ClientHelloMessage clientHello =
                (ClientHelloMessage)
                        WorkflowTraceUtil.getFirstSendMessage(
                                HandshakeMessageType.CLIENT_HELLO, workflowTrace);
        SignatureAndHashAlgorithmsExtensionMessage algorithmsExtension =
                clientHello.getExtension(SignatureAndHashAlgorithmsExtensionMessage.class);
        algorithmsExtension.setSignatureAndHashAlgorithms(
                Modifiable.insert(new byte[] {(byte) 0xfe, 0x44}, 0));

        runner.execute(workflowTrace, c).validateFinal(Validator::executedAsPlanned);
    }
}
