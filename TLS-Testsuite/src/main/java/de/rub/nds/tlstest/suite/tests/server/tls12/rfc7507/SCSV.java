package de.rub.nds.tlstest.suite.tests.server.tls12.rfc7507;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsscanner.report.result.VersionSuiteListPair;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.*;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.AnnotatedState;
import de.rub.nds.tlstest.framework.execution.AnnotatedStateContainer;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;

import java.util.ArrayList;
import java.util.List;

@RFC(number = 7507, section = "3. Server Behavior")
@ServerTest
public class SCSV extends Tls12Test {

    public ConditionEvaluationResult supportsOtherTlsVersions() {
        List<ProtocolVersion> versions = context.getConfig().getSiteReport().getVersions();
        if (versions.contains(ProtocolVersion.TLS10) || versions.contains(ProtocolVersion.TLS11)) {
            return ConditionEvaluationResult.enabled("Other versions are supported");
        }
        return ConditionEvaluationResult.disabled("No other TLS versions are supported");
    }

    @TlsTest(description = "If TLS_FALLBACK_SCSV appears in ClientHello.cipher_suites and the highest protocol version " +
            "supported by the server is higher than the version indicated in ClientHello.client_version, " +
            "the server MUST respond with a fatal inappropriate_fallback alert (unless it responds with a fatal protocol_version alert " +
            "because the version indicated in ClientHello.client_version is unsupported). " +
            "The record layer version number for this alert MUST be set to either ClientHello.client_version " +
            "(as it would for the Server Hello message if the server was continuing the handshake) " +
            "or to the record layer version number used by the client.", securitySeverity = SeverityLevel.MEDIUM)
    @MethodCondition(method = "supportsOtherTlsVersions")
    @KeyExchange(supported = KeyExchangeType.ALL12)
    public void includeFallbackSCSV(WorkflowRunner runner) {
        List<VersionSuiteListPair> olderCipherSuites = new ArrayList<>(context.getConfig().getSiteReport().getVersionSuitePairs());
        olderCipherSuites.removeIf(i -> i.getVersion() != ProtocolVersion.TLS10 && i.getVersion() != ProtocolVersion.TLS11);

        AnnotatedStateContainer container = new AnnotatedStateContainer();

        for (VersionSuiteListPair versionSuite : olderCipherSuites) {
            for (CipherSuite cipherSuite : versionSuite.getCiphersuiteList()) {
                Config c = context.getConfig().createConfig();
                c.setDefaultSelectedCipherSuite(cipherSuite);
                c.setDefaultClientSupportedCiphersuites(cipherSuite, CipherSuite.TLS_FALLBACK_SCSV);
                c.setDefaultSelectedProtocolVersion(versionSuite.getVersion());

                ClientHelloMessage clientHello = new ClientHelloMessage(c);
                clientHello.setProtocolVersion(Modifiable.explicit(versionSuite.getVersion().getValue()));

                WorkflowTrace trace = new WorkflowTrace();
                trace.addTlsActions(
                        new SendAction(clientHello),
                        new ReceiveAction(new AlertMessage())
                );

                AnnotatedState annotatedState = new AnnotatedState(new State(c, trace));
                annotatedState.setInspectedCipherSuite(cipherSuite);
                container.add(annotatedState);
            }
        }

        runner.execute(container).validateFinal(i -> {
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
            "or to the record layer version number used by the client.", securitySeverity = SeverityLevel.MEDIUM)
    @MethodCondition(method = "supportsOtherTlsVersions")
    @KeyExchange(supported = KeyExchangeType.ALL12)
    public void includeFallbackSCSV_nonRecommendedCipherSuiteOrder(WorkflowRunner runner) {
        List<VersionSuiteListPair> olderCipherSuites = new ArrayList<>(context.getConfig().getSiteReport().getVersionSuitePairs());
        olderCipherSuites.removeIf(i -> i.getVersion() != ProtocolVersion.TLS10 && i.getVersion() != ProtocolVersion.TLS11);

        AnnotatedStateContainer container = new AnnotatedStateContainer();

        for (VersionSuiteListPair versionSuite : olderCipherSuites) {
            for (CipherSuite cipherSuite : versionSuite.getCiphersuiteList()) {
                Config c = context.getConfig().createConfig();
                c.setDefaultSelectedCipherSuite(cipherSuite);
                c.setDefaultClientSupportedCiphersuites(CipherSuite.TLS_FALLBACK_SCSV, cipherSuite);
                c.setDefaultSelectedProtocolVersion(versionSuite.getVersion());

                ClientHelloMessage clientHello = new ClientHelloMessage(c);
                clientHello.setProtocolVersion(Modifiable.explicit(versionSuite.getVersion().getValue()));

                WorkflowTrace trace = new WorkflowTrace();
                trace.addTlsActions(
                        new SendAction(clientHello),
                        new ReceiveAction(new AlertMessage())
                );

                AnnotatedState annotatedState = new AnnotatedState(new State(c, trace));
                annotatedState.setInspectedCipherSuite(cipherSuite);
                container.add(annotatedState);
            }
        }

        runner.execute(container).validateFinal(i -> {
            Validator.receivedFatalAlert(i);

            AlertMessage alert = i.getWorkflowTrace().getFirstReceivedMessage(AlertMessage.class);
            Validator.testAlertDescription(i, AlertDescription.INAPPROPRIATE_FALLBACK, alert);
        });
    }
}
