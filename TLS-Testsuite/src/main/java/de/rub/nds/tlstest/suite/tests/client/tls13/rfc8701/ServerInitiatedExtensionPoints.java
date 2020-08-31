package de.rub.nds.tlstest.suite.tests.client.tls13.rfc8701;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.EncryptedExtensionsMessage;
import de.rub.nds.tlsattacker.core.protocol.message.NewSessionTicketMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.GreaseExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SupportedVersionsExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.ClientTest;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.AnnotatedStateContainer;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@ClientTest
@RFC(number = 8701, section = "4. Server-Initiated Extension Points")
public class ServerInitiatedExtensionPoints extends Tls13Test {

    @TlsTest(description = "When sending a NewSessionTicket message in TLS 1.3, a server " +
            "MAY select one or more GREASE extension values and advertise them as extensions " +
            "with varying length and contents. " +
            "When processing a CertiﬁcateRequest or NewSessionTicket, " +
            "clients MUST NOT treat GREASE values diﬀerently from any unknown value.", interoperabilitySeverity = SeverityLevel.CRITICAL)
    public void advertiseGreaseExtensionsInSessionTicket(WorkflowRunner runner) {
        runner.replaceSelectedCiphersuite = true;

        Config c = this.getConfig();
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        workflowTrace.addTlsActions(new SendAction(new NewSessionTicketMessage(c)));

        AnnotatedStateContainer container = new AnnotatedStateContainer();

        List<ExtensionType> types = Arrays.stream(ExtensionType.values()).filter(ExtensionType::isGrease).collect(Collectors.toList());
        for (ExtensionType type : types) {
            runner.setStateModifier(i -> {
                NewSessionTicketMessage msg = i.getWorkflowTrace().getFirstSendMessage(NewSessionTicketMessage.class);
                msg.addExtension(new GreaseExtensionMessage(type, 25));
                i.addAdditionalTestInfo(type.name());
                return null;
            });

            container.addAll(runner.prepare(workflowTrace, c));
        }

        runner.execute(container).validateFinal(Validator::executedAsPlanned);
    }

    @TlsTest(description = "Clients MUST reject GREASE values when negotiated by the server. " +
            "In particular, the client MUST fail the connection " +
            "if a GREASE value appears in any of the following: " +
            "The \"version\" value in a ServerHello or HelloRetryRequest", interoperabilitySeverity = SeverityLevel.CRITICAL)
    public void selectGreaseVersion(WorkflowRunner runner) {
        runner.replaceSelectedCiphersuite = true;
        Config c = this.getConfig();
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsActions(new ReceiveAction(new AlertMessage()));

        ClientHelloMessage ch = context.getReceivedClientHelloMessage();

        List<ProtocolVersion> versions = ProtocolVersion.getProtocolVersions(ch.getExtension(SupportedVersionsExtensionMessage.class).getSupportedVersions().getValue());
        versions = versions.stream().filter(ProtocolVersion::isGrease).collect(Collectors.toList());
        ProtocolVersion v;
        if (versions.size() > 0) {
            v = versions.get(0);
        } else {
            v = ProtocolVersion.GREASE_09;
        }
        runner.setStateModifier(i -> {
            ServerHelloMessage sh = i.getWorkflowTrace().getFirstSendMessage(ServerHelloMessage.class);
            SupportedVersionsExtensionMessage ext = sh.getExtension(SupportedVersionsExtensionMessage.class);
            ext.setSupportedVersions(Modifiable.explicit(v.getValue()));
            return null;
        });

        runner.execute(workflowTrace, c).validateFinal(Validator::receivedFatalAlert);
    }


    @TlsTest(description = "Clients MUST reject GREASE values when negotiated by the server. " +
            "In particular, the client MUST fail the connection " +
            "if a GREASE value appears in any of the following: " +
            "The \"cipher_suite\" value in a ServerHello", interoperabilitySeverity = SeverityLevel.CRITICAL)
    public void selectGreaseCipherSuite(WorkflowRunner runner) {
        runner.replaceSelectedCiphersuite = true;
        Config c = this.getConfig();
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsActions(new ReceiveAction(new AlertMessage()));

        List<CipherSuite> greaseCipherSuites = context.getSiteReport().getCipherSuites().stream().filter(CipherSuite::isGrease).collect(Collectors.toList());
        CipherSuite cs;
        if (greaseCipherSuites.size() > 0) {
            cs = greaseCipherSuites.get(0);
        } else {
            cs = CipherSuite.GREASE_08;
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
            "Any ServerHello extension", interoperabilitySeverity = SeverityLevel.CRITICAL)
    public void sendServerHelloGreaseExtension(WorkflowRunner runner) {
        runner.replaceSelectedCiphersuite = true;
        Config c = this.getConfig();
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        workflowTrace.addTlsActions(new ReceiveAction(new AlertMessage()));

        runner.setStateModifier(i -> {
            ServerHelloMessage sh = i.getWorkflowTrace().getFirstSendMessage(ServerHelloMessage.class);
            sh.addExtension(new GreaseExtensionMessage(ExtensionType.GREASE_03, 25));
            return null;
        });

        runner.execute(workflowTrace, c).validateFinal(Validator::receivedFatalAlert);
    }

    @TlsTest(description = "Clients MUST reject GREASE values when negotiated by the server. " +
            "In particular, the client MUST fail the connection " +
            "if a GREASE value appears in any of the following: " +
            "Any EncryptedExtensions extension", interoperabilitySeverity = SeverityLevel.CRITICAL)
    public void sendEncryptedExtensionsGreaseExtension(WorkflowRunner runner) {
        runner.replaceSelectedCiphersuite = true;
        Config c = this.getConfig();
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
        workflowTrace.addTlsActions(new ReceiveAction(new AlertMessage()));

        runner.setStateModifier(i -> {
            EncryptedExtensionsMessage sh = i.getWorkflowTrace().getFirstSendMessage(EncryptedExtensionsMessage.class);
            sh.addExtension(new GreaseExtensionMessage(ExtensionType.GREASE_03, 25));
            return null;
        });

        runner.execute(workflowTrace, c).validateFinal(Validator::receivedFatalAlert);
    }

    @TlsTest(description = "Clients MUST reject GREASE values when negotiated by the server. " +
            "In particular, the client MUST fail the connection " +
            "if a GREASE value appears in any of the following: " +
            "The signature algorithm in a server CertiﬁcateVerify signature in TLS 1.3", interoperabilitySeverity = SeverityLevel.CRITICAL)
    public void sendCertificateVerifyGreaseSignatureAlgorithm(WorkflowRunner runner) {
        runner.replaceSelectedCiphersuite = true;
        Config c = this.getConfig();
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        workflowTrace.addTlsActions(new ReceiveAction(new AlertMessage()));

        runner.setStateModifier(i -> {
            CertificateVerifyMessage sh = i.getWorkflowTrace().getFirstSendMessage(CertificateVerifyMessage.class);
            sh.setSignatureHashAlgorithm(Modifiable.explicit(SignatureAndHashAlgorithm.GREASE_03.getByteValue()));
            return null;
        });

        runner.execute(workflowTrace, c).validateFinal(Validator::receivedFatalAlert);
    }
}
