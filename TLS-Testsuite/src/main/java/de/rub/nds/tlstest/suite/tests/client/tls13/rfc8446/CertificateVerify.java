/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.client.tls13.rfc8446;

import de.rub.nds.anvilcore.annotation.*;
import de.rub.nds.anvilcore.coffee4j.model.ModelFromScope;
import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.ClientFeatureExtractionResult;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.derivationParameter.SigAndHashDerivation;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@ClientTest
public class CertificateVerify extends Tls13Test {

    public ConditionEvaluationResult supportsLegacyRSASHAlgorithms() {
        List<SignatureAndHashAlgorithm> algos =
                ((ClientFeatureExtractionResult) context.getFeatureExtractionResult())
                        .getAdvertisedSignatureAndHashAlgorithms();
        algos =
                algos.stream()
                        .filter(i -> i.getSignatureAlgorithm() == SignatureAlgorithm.RSA)
                        .collect(Collectors.toList());

        if (algos.size() > 0) {
            return ConditionEvaluationResult.enabled("");
        }
        return ConditionEvaluationResult.disabled(
                "Client does not support legacy rsa signature and hash algorithms");
    }

    public List<DerivationParameter<Config, SignatureAndHashAlgorithm>> getLegacyRSASAHAlgorithms(
            DerivationScope scope) {
        List<DerivationParameter<Config, SignatureAndHashAlgorithm>> parameterValues =
                new LinkedList<>();
        for (SignatureAndHashAlgorithm algo :
                ((ClientFeatureExtractionResult) context.getFeatureExtractionResult())
                        .getAdvertisedSignatureAndHashAlgorithms()) {
            if (algo.getSignatureAlgorithm() == SignatureAlgorithm.RSA) {
                parameterValues.add(new SigAndHashDerivation(algo));
            }
        }
        return parameterValues;
    }

    @AnvilTest(id = "8446-oN7MGas4sq")
    @IncludeParameter("SIG_HASH_ALGORIHTM")
    @ExplicitValues(
            affectedIdentifiers = "SIG_HASH_ALGORIHTM",
            methods = "getLegacyRSASAHAlgorithms")
    @ManualConfig(identifiers = "SIG_HASH_ALGORIHTM")
    @MethodCondition(method = "supportsLegacyRSASHAlgorithms")
    public void selectLegacyRSASignatureAlgorithm(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        SignatureAndHashAlgorithm selsectedLegacySigHash =
                parameterCombination.getParameter(SigAndHashDerivation.class).getSelectedValue();

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsActions(new ReceiveAction(new AlertMessage()));
        workflowTrace
                .getFirstSendMessage(CertificateVerifyMessage.class)
                .setSignatureHashAlgorithm(
                        Modifiable.explicit(selsectedLegacySigHash.getByteValue()));

        runner.execute(workflowTrace, c).validateFinal(Validator::receivedFatalAlert);
    }

    public ConditionEvaluationResult supportsLegacyECDSASAHAlgorithms() {
        if (((ClientFeatureExtractionResult) context.getFeatureExtractionResult())
                .getAdvertisedSignatureAndHashAlgorithms()
                .contains(SignatureAndHashAlgorithm.ECDSA_SHA1)) {
            return ConditionEvaluationResult.enabled("");
        }
        return ConditionEvaluationResult.disabled(
                "Client does not support legacy rsa signature and hash algorithms");
    }

    @AnvilTest(id = "8446-LNoEKntfip")
    @MethodCondition(method = "supportsLegacyECDSASAHAlgorithms")
    public void selectLegacyECDSASignatureAlgorithm(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        c.setAutoAdjustSignatureAndHashAlgorithm(false);
        c.setDefaultSelectedSignatureAndHashAlgorithm(SignatureAndHashAlgorithm.ECDSA_SHA1);
        c.setPreferredCertificateSignatureType(CertificateKeyType.ECDSA);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsActions(new ReceiveAction(new AlertMessage()));

        runner.execute(workflowTrace, c).validateFinal(Validator::receivedFatalAlert);
    }

    @AnvilTest(id = "8446-cEg5hNM3Lm")
    @ModelFromScope(modelType = "CERTIFICATE")
    @IncludeParameter("SIGNATURE_BITMASK")
    public void invalidSignature(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        byte[] bitmask = parameterCombination.buildBitmask();

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsActions(new ReceiveAction(new AlertMessage()));

        CertificateVerifyMessage msg =
                workflowTrace.getFirstSendMessage(CertificateVerifyMessage.class);
        msg.setSignature(Modifiable.xor(bitmask, 0));

        runner.execute(workflowTrace, c)
                .validateFinal(
                        i -> {
                            if (msg.getSignatureLength().getValue() < bitmask.length) {
                                // we can't determine the ECDSA signature length beforehand
                                // as trailing zeros may be stripped - the manipulation won't be
                                // applied in these cases which results in false positives
                                i.addAdditionalResultInfo("Bitmask exceeded signature length");
                                return;
                            }
                            Validator.receivedFatalAlert(i);

                            AlertMessage amsg =
                                    i.getWorkflowTrace()
                                            .getFirstReceivedMessage(AlertMessage.class);
                            Validator.testAlertDescription(i, AlertDescription.DECRYPT_ERROR, amsg);
                        });
    }

    public List<DerivationParameter> getUnproposedSignatureAndHashAlgorithms(
            DerivationScope scope) {
        List<DerivationParameter> unsupportedAlgorithms = new LinkedList<>();
        SignatureAndHashAlgorithm.getImplemented().stream()
                .filter(
                        algorithm ->
                                !((ClientFeatureExtractionResult)
                                                context.getFeatureExtractionResult())
                                        .getAdvertisedSignatureAndHashAlgorithms()
                                        .contains(algorithm))
                .filter(
                        algorithm ->
                                algorithm.getSignatureAlgorithm() != SignatureAlgorithm.ANONYMOUS)
                .forEach(
                        algorithm ->
                                unsupportedAlgorithms.add(new SigAndHashDerivation(algorithm)));
        return unsupportedAlgorithms;
    }

    @AnvilTest(id = "8446-NYgNsg97bX")
    @ModelFromScope(modelType = "CERTIFICATE")
    @ExplicitValues(
            affectedIdentifiers = "SIG_HASH_ALGORIHTM",
            methods = "getUnproposedSignatureAndHashAlgorithms")
    public void acceptsUnproposedSignatureAndHash(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        WorkflowTrace workflowTrace =
                runner.generateWorkflowTraceUntilReceivingMessage(
                        WorkflowTraceType.HANDSHAKE, ProtocolMessageType.CHANGE_CIPHER_SPEC);
        workflowTrace.addTlsAction(new ReceiveAction(new AlertMessage()));

        runner.execute(workflowTrace, c)
                .validateFinal(
                        i -> {
                            Validator.receivedFatalAlert(i);
                        });
    }

    @AnvilTest(id = "8446-HKxd74FVbC")
    public void emptySignature(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        WorkflowTrace trace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        trace.addTlsActions(new ReceiveAction(new AlertMessage()));

        trace.getFirstSendMessage(CertificateVerifyMessage.class)
                .setSignature(Modifiable.explicit(new byte[] {}));

        runner.execute(trace, c)
                .validateFinal(
                        i -> {
                            Validator.receivedFatalAlert(i);

                            AlertMessage alert =
                                    i.getWorkflowTrace()
                                            .getFirstReceivedMessage(AlertMessage.class);
                            Validator.testAlertDescription(
                                    i, AlertDescription.DECRYPT_ERROR, alert);
                        });
    }

    @AnvilTest(id = "8446-CZWhi6PJvQ")
    public void emptySigAlgorithm(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        WorkflowTrace trace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        trace.addTlsActions(new ReceiveAction(new AlertMessage()));

        trace.getFirstSendMessage(CertificateVerifyMessage.class)
                .setSignatureHashAlgorithm(Modifiable.explicit(new byte[] {}));

        runner.execute(trace, c).validateFinal(Validator::receivedFatalAlert);
    }

    @AnvilTest(id = "8446-AptaW3C62X")
    public void emptyBoth(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        WorkflowTrace trace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        trace.addTlsActions(new ReceiveAction(new AlertMessage()));

        trace.getFirstSendMessage(CertificateVerifyMessage.class)
                .setSignatureHashAlgorithm(Modifiable.explicit(new byte[] {}));
        trace.getFirstSendMessage(CertificateVerifyMessage.class)
                .setSignature(Modifiable.explicit(new byte[] {}));

        runner.execute(trace, c).validateFinal(Validator::receivedFatalAlert);
    }
}
