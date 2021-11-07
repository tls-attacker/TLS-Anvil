/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.server.tls12.rfc7507;

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
import de.rub.nds.tlsscanner.serverscanner.report.result.VersionSuiteListPair;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.ExplicitValues;
import de.rub.nds.tlstest.framework.annotations.MethodCondition;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.ServerTest;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.annotations.categories.AlertCategory;
import de.rub.nds.tlstest.framework.annotations.categories.ComplianceCategory;
import de.rub.nds.tlstest.framework.annotations.categories.CryptoCategory;
import de.rub.nds.tlstest.framework.annotations.categories.DeprecatedFeatureCategory;
import de.rub.nds.tlstest.framework.annotations.categories.HandshakeCategory;
import de.rub.nds.tlstest.framework.annotations.categories.InteroperabilityCategory;
import de.rub.nds.tlstest.framework.annotations.categories.MessageStructureCategory;
import de.rub.nds.tlstest.framework.annotations.categories.SecurityCategory;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.DerivationScope;
import de.rub.nds.tlstest.framework.model.DerivationType;
import de.rub.nds.tlstest.framework.model.derivationParameter.CipherSuiteDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.DerivationParameter;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;
import de.rub.nds.tlstest.framework.annotations.categories.RecordLayerCategory;

@RFC(number = 7507, section = "3. Server Behavior")
@ServerTest
public class SCSV extends Tls12Test {

    public ConditionEvaluationResult supportsOtherTlsVersions() {
        List<ProtocolVersion> versions = context.getSiteReport().getVersions();
        if (versions.contains(ProtocolVersion.TLS10) || versions.contains(ProtocolVersion.TLS11)) {
            return ConditionEvaluationResult.enabled("Other versions are supported");
        }
        return ConditionEvaluationResult.disabled("No other TLS versions are supported");
    }
    
    public List<DerivationParameter> getOldCiphersuites(DerivationScope scope) {
        List<DerivationParameter> parameterValues = new LinkedList<>();
        Set<CipherSuite> olderCipherSuites = new HashSet<>();
                
        List<VersionSuiteListPair> olderPairs = new ArrayList<>(context.getSiteReport().getVersionSuitePairs());
        olderPairs.removeIf(i -> i.getVersion() != ProtocolVersion.TLS10 && i.getVersion() != ProtocolVersion.TLS11);
        for(VersionSuiteListPair pair: olderPairs) {
            olderCipherSuites.addAll(pair.getCipherSuiteList());
        }
        
        for(CipherSuite cipherSuite: olderCipherSuites) {
            parameterValues.add(new CipherSuiteDerivation(cipherSuite));
        }
        
        return parameterValues;
    }
    
    public ProtocolVersion getVersionForCipherSuite(CipherSuite cipherSuite) {
        List<VersionSuiteListPair> olderPairs = new ArrayList<>(context.getSiteReport().getVersionSuitePairs());
        olderPairs.removeIf(i -> i.getVersion() != ProtocolVersion.TLS10 && i.getVersion() != ProtocolVersion.TLS11);
        for(VersionSuiteListPair versionSuite: olderPairs) {
            if(versionSuite.getCipherSuiteList().contains(cipherSuite)) {
                return versionSuite.getVersion();
            }
        }
        return null;
    }

    @TlsTest(description = "If TLS_FALLBACK_SCSV appears in ClientHello.cipher_suites and the highest protocol version " +
            "supported by the server is higher than the version indicated in ClientHello.client_version, " +
            "the server MUST respond with a fatal inappropriate_fallback alert (unless it responds with a fatal protocol_version alert " +
            "because the version indicated in ClientHello.client_version is unsupported). " +
            "The record layer version number for this alert MUST be set to either ClientHello.client_version " +
            "(as it would for the Server Hello message if the server was continuing the handshake) " +
            "or to the record layer version number used by the client.")
    @ExplicitValues(affectedTypes=DerivationType.CIPHERSUITE, methods="getOldCiphersuites")
    @MethodCondition(method = "supportsOtherTlsVersions")
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.MEDIUM)
    @SecurityCategory(SeverityLevel.HIGH)
    public void includeFallbackSCSV(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        CipherSuite cipherSuite = derivationContainer.getDerivation(CipherSuiteDerivation.class).getSelectedValue();
        c.setDefaultSelectedProtocolVersion(getVersionForCipherSuite(cipherSuite));

        c.setDefaultSelectedCipherSuite(cipherSuite);
        c.setDefaultClientSupportedCipherSuites(cipherSuite, CipherSuite.TLS_FALLBACK_SCSV);

        ClientHelloMessage clientHello = new ClientHelloMessage(c);
        clientHello.setProtocolVersion(Modifiable.explicit(getVersionForCipherSuite(cipherSuite).getValue()));

        WorkflowTrace trace = new WorkflowTrace();
        trace.addTlsActions(
            new SendAction(clientHello),
            new ReceiveAction(new AlertMessage())
        );
        
        runner.execute(trace, c).validateFinal(i -> {
            Validator.receivedFatalAlert(i);

            AlertMessage alert = i.getWorkflowTrace().getFirstReceivedMessage(AlertMessage.class);
            Validator.testAlertDescription(i, AlertDescription.INAPPROPRIATE_FALLBACK, alert);
        });
    }

    @TlsTest(description = "If TLS_FALLBACK_SCSV appears in ClientHello.cipher_suites and the highest protocol version " +
            "supported by the server is higher than the version indicated in ClientHello.client_version, " +
            "the server MUST respond with a fatal inappropriate_fallback alert (unless it responds with a fatal protocol_version alert " +
            "because the version indicated in ClientHello.client_version is unsupported). " +
            "The record layer version number for this alert MUST be set to either ClientHello.client_version " +
            "(as it would for the Server Hello message if the server was continuing the handshake) " +
            "or to the record layer version number used by the client.")
    @ExplicitValues(affectedTypes=DerivationType.CIPHERSUITE, methods="getOldCiphersuites")
    @MethodCondition(method = "supportsOtherTlsVersions")
    @HandshakeCategory(SeverityLevel.MEDIUM)
    @AlertCategory(SeverityLevel.MEDIUM)
    @ComplianceCategory(SeverityLevel.MEDIUM)
    @SecurityCategory(SeverityLevel.HIGH)
    public void includeFallbackSCSV_nonRecommendedCipherSuiteOrder(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        CipherSuite cipherSuite = derivationContainer.getDerivation(CipherSuiteDerivation.class).getSelectedValue();
        c.setDefaultSelectedProtocolVersion(getVersionForCipherSuite(cipherSuite));

        c.setDefaultSelectedCipherSuite(cipherSuite);
        c.setDefaultClientSupportedCipherSuites(CipherSuite.TLS_FALLBACK_SCSV, cipherSuite);

        ClientHelloMessage clientHello = new ClientHelloMessage(c);
        clientHello.setProtocolVersion(Modifiable.explicit(getVersionForCipherSuite(cipherSuite).getValue()));

        WorkflowTrace trace = new WorkflowTrace();
        trace.addTlsActions(
            new SendAction(clientHello),
            new ReceiveAction(new AlertMessage())
        );
        
        runner.execute(trace, c).validateFinal(i -> {
            Validator.receivedFatalAlert(i);

            AlertMessage alert = i.getWorkflowTrace().getFirstReceivedMessage(AlertMessage.class);
            Validator.testAlertDescription(i, AlertDescription.INAPPROPRIATE_FALLBACK, alert);
        });
    }
}
