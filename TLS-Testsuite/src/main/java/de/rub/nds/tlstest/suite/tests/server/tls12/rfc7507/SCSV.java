/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.server.tls12.rfc7507;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.ExplicitValues;
import de.rub.nds.anvilcore.annotation.MethodCondition;
import de.rub.nds.anvilcore.annotation.ServerTest;
import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsscanner.core.probe.result.VersionSuiteListPair;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.derivationParameter.CipherSuiteDerivation;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import java.util.*;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@ServerTest
public class SCSV extends Tls12Test {

    public ConditionEvaluationResult supportsOtherTlsVersions() {
        Set<ProtocolVersion> versions = context.getFeatureExtractionResult().getSupportedVersions();
        if (versions.contains(ProtocolVersion.TLS10) || versions.contains(ProtocolVersion.TLS11)) {
            return ConditionEvaluationResult.enabled("Other versions are supported");
        }
        return ConditionEvaluationResult.disabled("No other TLS versions are supported");
    }

    public List<DerivationParameter<Config, CipherSuite>> getOldCiphersuites(
            DerivationScope scope) {
        List<DerivationParameter<Config, CipherSuite>> parameterValues = new LinkedList<>();
        Set<CipherSuite> olderCipherSuites = new HashSet<>();

        List<VersionSuiteListPair> olderPairs =
                new ArrayList<>(context.getFeatureExtractionResult().getVersionSuitePairs());
        olderPairs.removeIf(
                i ->
                        i.getVersion() != ProtocolVersion.TLS10
                                && i.getVersion() != ProtocolVersion.TLS11);
        for (VersionSuiteListPair pair : olderPairs) {
            olderCipherSuites.addAll(pair.getCipherSuiteList());
        }

        for (CipherSuite cipherSuite : olderCipherSuites) {
            parameterValues.add(new CipherSuiteDerivation(cipherSuite));
        }

        return parameterValues;
    }

    public ProtocolVersion getVersionForCipherSuite(CipherSuite cipherSuite) {
        List<VersionSuiteListPair> olderPairs =
                new ArrayList<>(context.getFeatureExtractionResult().getVersionSuitePairs());
        olderPairs.removeIf(
                i ->
                        i.getVersion() != ProtocolVersion.TLS10
                                && i.getVersion() != ProtocolVersion.TLS11);
        for (VersionSuiteListPair versionSuite : olderPairs) {
            if (versionSuite.getCipherSuiteList().contains(cipherSuite)) {
                return versionSuite.getVersion();
            }
        }
        return null;
    }

    @AnvilTest
    @ExplicitValues(affectedIdentifiers = "CIPHER_SUITE", methods = "getOldCiphersuites")
    @MethodCondition(method = "supportsOtherTlsVersions")
    public void includeFallbackSCSV(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        CipherSuite cipherSuite =
                parameterCombination.getParameter(CipherSuiteDerivation.class).getSelectedValue();
        c.setDefaultSelectedProtocolVersion(getVersionForCipherSuite(cipherSuite));

        c.setDefaultSelectedCipherSuite(cipherSuite);
        c.setDefaultClientSupportedCipherSuites(cipherSuite, CipherSuite.TLS_FALLBACK_SCSV);

        ClientHelloMessage clientHello = new ClientHelloMessage(c);
        clientHello.setProtocolVersion(
                Modifiable.explicit(getVersionForCipherSuite(cipherSuite).getValue()));

        WorkflowTrace trace = new WorkflowTrace();
        trace.addTlsActions(new SendAction(clientHello), new ReceiveAction(new AlertMessage()));

        runner.execute(trace, c)
                .validateFinal(
                        i -> {
                            Validator.receivedFatalAlert(i);

                            AlertMessage alert =
                                    i.getWorkflowTrace()
                                            .getFirstReceivedMessage(AlertMessage.class);
                            Validator.testAlertDescription(
                                    i, AlertDescription.INAPPROPRIATE_FALLBACK, alert);
                        });
    }

    @AnvilTest
    @ExplicitValues(affectedIdentifiers = "CIPHER_SUITE", methods = "getOldCiphersuites")
    @MethodCondition(method = "supportsOtherTlsVersions")
    public void includeFallbackSCSV_nonRecommendedCipherSuiteOrder(
            ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        CipherSuite cipherSuite =
                parameterCombination.getParameter(CipherSuiteDerivation.class).getSelectedValue();
        c.setDefaultSelectedProtocolVersion(getVersionForCipherSuite(cipherSuite));

        c.setDefaultSelectedCipherSuite(cipherSuite);
        c.setDefaultClientSupportedCipherSuites(CipherSuite.TLS_FALLBACK_SCSV, cipherSuite);

        ClientHelloMessage clientHello = new ClientHelloMessage(c);
        clientHello.setProtocolVersion(
                Modifiable.explicit(getVersionForCipherSuite(cipherSuite).getValue()));

        WorkflowTrace trace = new WorkflowTrace();
        trace.addTlsActions(new SendAction(clientHello), new ReceiveAction(new AlertMessage()));

        runner.execute(trace, c)
                .validateFinal(
                        i -> {
                            Validator.receivedFatalAlert(i);

                            AlertMessage alert =
                                    i.getWorkflowTrace()
                                            .getFirstReceivedMessage(AlertMessage.class);
                            Validator.testAlertDescription(
                                    i, AlertDescription.INAPPROPRIATE_FALLBACK, alert);
                        });
    }
}
