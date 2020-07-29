package de.rub.nds.tlstest.suite.tests.client.tls12.rfc8701;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.EncryptedExtensionsMessage;
import de.rub.nds.tlsattacker.core.protocol.message.NewSessionTicketMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EllipticCurvesExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.GreaseExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SupportedVersionsExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.ClientTest;
import de.rub.nds.tlstest.framework.annotations.KeyExchange;
import de.rub.nds.tlstest.framework.annotations.MethodCondition;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.constants.KeyExchangeType;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.AnnotatedStateContainer;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@ClientTest
@RFC(number = 8701, section = "4. Server-Initiated Extension Points")
public class ServerInitiatedExtensionPoints extends Tls12Test {

    @TlsTest(description = "Clients MUST reject GREASE values when negotiated by the server. " +
            "In particular, the client MUST fail the connection " +
            "if a GREASE value appears in any of the following: " +
            "The \"version\" value in a ServerHello or HelloRetryRequest", interoperabilitySeverity = SeverityLevel.HIGH)
    public void selectGreaseVersion(WorkflowRunner runner) {
        runner.replaceSelectedCiphersuite = true;
        Config c = this.getConfig();
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsActions(new ReceiveAction(new AlertMessage()));

        runner.setStateModifier(i -> {
            ServerHelloMessage sh = i.getWorkflowTrace().getFirstSendMessage(ServerHelloMessage.class);
            sh.setProtocolVersion(Modifiable.explicit(ProtocolVersion.GREASE_06.getValue()));
            return null;
        });

        runner.execute(workflowTrace, c).validateFinal(Validator::receivedFatalAlert);
    }

    @TlsTest(description = "Clients MUST reject GREASE values when negotiated by the server. " +
            "In particular, the client MUST fail the connection " +
            "if a GREASE value appears in any of the following: " +
            "The \"cipher_suite\" value in a ServerHello", interoperabilitySeverity = SeverityLevel.HIGH)
    public void selectGreaseCipherSuite(WorkflowRunner runner) {
        runner.replaceSelectedCiphersuite = true;
        Config c = this.getConfig();
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsActions(new ReceiveAction(new AlertMessage()));

        List<CipherSuite> greaseCipherSuites = context.getConfig().getSiteReport().getCipherSuites().stream().filter(CipherSuite::isGrease).collect(Collectors.toList());
        CipherSuite cs;
        if (greaseCipherSuites.size() > 0) {
            cs = greaseCipherSuites.get(0);
        } else {
            cs = CipherSuite.GREASE_03;
        }

        runner.setStateModifier(i -> {
            ServerHelloMessage sh = i.getWorkflowTrace().getFirstSendMessage(ServerHelloMessage.class);
            sh.setSelectedCipherSuite(Modifiable.explicit(cs.getByteValue()));
            return null;
        });

        runner.execute(workflowTrace, c).validateFinal(Validator::receivedFatalAlert);
    }

    @TlsTest(description = "Clients MUST reject GREASE values when negotiated by the server. " +
            "In particular, the client MUST fail the connection " +
            "if a GREASE value appears in any of the following: " +
            "Any ServerHello extension", interoperabilitySeverity = SeverityLevel.HIGH)
    public void sendServerHelloGreaseExtension(WorkflowRunner runner) {
        runner.replaceSelectedCiphersuite = true;
        Config c = this.getConfig();
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);

        runner.setStateModifier(i -> {
            ServerHelloMessage sh = i.getWorkflowTrace().getFirstSendMessage(ServerHelloMessage.class);
            sh.addExtension(new GreaseExtensionMessage(ExtensionType.GREASE_03, 25));
            return null;
        });

        runner.execute(workflowTrace, c).validateFinal(Validator::executedAsPlanned);
    }


    @TlsTest(description = "Clients MUST reject GREASE values when negotiated by the server. " +
            "In particular, the client MUST fail the connection " +
            "if a GREASE value appears in any of the following: " +
            "The \"namedcurve\" value in a ServerKeyExchange for an Ephemeral Elliptic Curve DiﬃeHellman (ECDHE) " +
            "cipher in TLS 1.2 [RFC5246] or earlier", interoperabilitySeverity = SeverityLevel.HIGH)
    @KeyExchange(supported = KeyExchangeType.ECDH, requiresServerKeyExchMsg = true)
    public void selectGreaseNamedGroup(WorkflowRunner runner) {
        runner.replaceSelectedCiphersuite = true;
        Config c = this.getConfig();
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsActions(new ReceiveAction(new AlertMessage()));

        List<NamedGroup> supportedGroups = context.getConfig().getSiteReport().getSupportedNamedGroups().stream().filter(NamedGroup::isGrease).collect(Collectors.toList());
        NamedGroup ng;
        if (supportedGroups.size() > 0) {
            ng = supportedGroups.get(0);
        } else {
            ng = NamedGroup.GREASE_12;
        }

        runner.setStateModifier(i -> {
            ECDHEServerKeyExchangeMessage skx = i.getWorkflowTrace().getFirstSendMessage(ECDHEServerKeyExchangeMessage.class);
            skx.setNamedGroup(Modifiable.explicit(ng.getValue()));
            return null;
        });

        runner.execute(workflowTrace, c).validateFinal(Validator::receivedFatalAlert);
    }


    @TlsTest(description = "Clients MUST reject GREASE values when negotiated by the server. " +
            "In particular, the client MUST fail the connection " +
            "if a GREASE value appears in any of the following: " +
            "The signature algorithm in a ServerKeyExchange signature in TLS 1.2 or earlier", interoperabilitySeverity = SeverityLevel.HIGH)
    @KeyExchange(supported = KeyExchangeType.ALL12, requiresServerKeyExchMsg = true)
    public void selectGreaseSignatureAlgorithm(WorkflowRunner runner) {
        runner.replaceSelectedCiphersuite = true;
        Config c = this.getConfig();
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsActions(new ReceiveAction(new AlertMessage()));

        List<SignatureAndHashAlgorithm> supportedAlgs = context.getConfig().getSiteReport().getSupportedSignatureAndHashAlgorithms()
                .stream()
                .filter(SignatureAndHashAlgorithm::isGrease)
                .collect(Collectors.toList());
        SignatureAndHashAlgorithm alg;
        if (supportedAlgs.size() > 0) {
            alg = supportedAlgs.get(0);
        } else {
            alg = SignatureAndHashAlgorithm.GREASE_04;
        }

        runner.setStateModifier(i -> {
            ServerKeyExchangeMessage skx = i.getWorkflowTrace().getFirstSendMessage(ServerKeyExchangeMessage.class);
            skx.setSignatureAndHashAlgorithm(Modifiable.explicit(alg.getByteValue()));
            return null;
        });

        runner.execute(workflowTrace, c).validateFinal(Validator::receivedFatalAlert);
    }
}
