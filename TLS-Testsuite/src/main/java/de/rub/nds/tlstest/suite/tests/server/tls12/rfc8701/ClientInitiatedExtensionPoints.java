package de.rub.nds.tlstest.suite.tests.server.tls12.rfc8701;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.AlpnExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.GreaseExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.alpn.AlpnEntry;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.ServerTest;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.AnnotatedStateContainer;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

@ServerTest
@RFC(number = 8701, section = "3. Client-Initiated Extension Points")
public class ClientInitiatedExtensionPoints extends Tls12Test {

    @TlsTest(description = "A client MAY select one or more GREASE cipher suite values and advertise them in the \"cipher_suites\" ﬁeld." +
            "Servers MUST NOT negotiate any GREASE value when offﬀered in a ClientHello.", interoperabilitySeverity = SeverityLevel.HIGH)
    public void advertiseGreaseCiphersuites(WorkflowRunner runner) {
        runner.appendEachSupportedCiphersuiteToClientSupported = true;

        Config c = this.getConfig();
        c.setDefaultClientSupportedCiphersuites(Arrays.stream(CipherSuite.values()).filter(CipherSuite::isGrease).collect(Collectors.toList()));

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        runner.execute(workflowTrace, c).validateFinal(i -> {
            Validator.executedAsPlanned(i);

            assertEquals("Server selected wrong ciphersuite", i.getInspectedCipherSuite(), i.getState().getTlsContext().getSelectedCipherSuite());
        });
    }

    @TlsTest(description = "A client MAY select one or more GREASE extension values and advertise them as extensions with varying length and contents." +
            "Servers MUST NOT negotiate any GREASE value when offered in a ClientHello.", interoperabilitySeverity = SeverityLevel.HIGH)
    public void advertiseGreaseExtensions(WorkflowRunner runner) {
        runner.replaceSupportedCiphersuites = true;
        Config c = this.getConfig();

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        AnnotatedStateContainer container = new AnnotatedStateContainer();

        for (ExtensionType type : Arrays.stream(ExtensionType.values()).filter(i -> i.name().startsWith("GREASE")).collect(Collectors.toList())) {
            runner.setStateModifier(i -> {
                ClientHelloMessage ch = i.getWorkflowTrace().getFirstSendMessage(ClientHelloMessage.class);
                ch.addExtension(new GreaseExtensionMessage(type, 25));
                i.addAdditionalTestInfo(type.name());
                return null;
            });

            container.addAll(runner.prepare(workflowTrace, c));
        }


        runner.execute(container).validateFinal(i -> {
            Validator.executedAsPlanned(i);

            i.getState().getTlsContext().getNegotiatedExtensionSet().forEach(j -> {
                assertFalse("Server negotiated GREASE extension", j.name().startsWith("GREASE"));
            });
        });
    }

    @TlsTest(description = "A client MAY select one or more GREASE named group values and advertise them in the \"supported_groups\" extension, " +
            "if sent. It MAY also send KeyShareEntry values for a subset of those selected in the \"key_share\" extension. " +
            "For each of these, the \"key_exchange\" ﬁeld MAY be any value. " +
            "Servers MUST NOT negotiate any GREASE value when offered in a ClientHello.", interoperabilitySeverity = SeverityLevel.HIGH)
    public void advertiseGreaseNamedGroup(WorkflowRunner runner) {
        runner.replaceSupportedCiphersuites = true;

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        AnnotatedStateContainer container = new AnnotatedStateContainer();

        for (NamedGroup type : context.getSiteReport().getSupportedNamedGroups()) {
            if (!NamedGroup.getImplemented().contains(type)) continue;
            Config c = this.getConfig();
            List<NamedGroup> groups = Arrays.stream(NamedGroup.values()).filter(i -> i.isGrease() || i == type).collect(Collectors.toList());
            c.setDefaultClientNamedGroups(groups);
            runner.setStateModifier(i -> {
                i.addAdditionalTestInfo(type.name());
                return null;
            });
            container.addAll(runner.prepare(workflowTrace, c));
        }

        runner.execute(container).validateFinal(Validator::executedAsPlanned);
    }


    @TlsTest(description = "A client MAY select one or more GREASE signature algorithm values " +
            "and advertise them in the \"signature_algorithms\" or " +
            "\"signature_algorithms_cert\" extensions, if sent. " +
            "Servers MUST NOT negotiate any GREASE value when offered in a ClientHello.", interoperabilitySeverity = SeverityLevel.HIGH)
    public void advertiseGreaseSignatureAlgorithms(WorkflowRunner runner) {
        runner.replaceSupportedCiphersuites = true;

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        AnnotatedStateContainer container = new AnnotatedStateContainer();

        Config c = this.getConfig();
        c.getDefaultClientSupportedSignatureAndHashAlgorithms().addAll(
                Arrays.stream(SignatureAndHashAlgorithm.values())
                        .filter(SignatureAndHashAlgorithm::isGrease)
                        .collect(Collectors.toList())
        );

        container.addAll(runner.prepare(workflowTrace, c));

        runner.execute(container).validateFinal(i -> {
            Validator.executedAsPlanned(i);

            ServerKeyExchangeMessage skx = i.getWorkflowTrace().getFirstReceivedMessage(ServerKeyExchangeMessage.class);
            if (skx == null) return;
            assertFalse("Server selected GREASE signature and hash algorithm", SignatureAndHashAlgorithm.getSignatureAndHashAlgorithm(skx.getSignatureAndHashAlgorithm().getValue()).isGrease());
        });
    }

    @TlsTest(description = "A client MAY select one or more GREASE ALPN identiﬁers " +
            "and advertise them in the \"application_layer_protocol_negotiation\" extension, if sent. " +
            "Servers MUST NOT negotiate any GREASE value when offered in a ClientHello.", interoperabilitySeverity = SeverityLevel.HIGH)
    public void advertiseGreaseALPNIdentifiers(WorkflowRunner runner) {
        runner.replaceSupportedCiphersuites = true;

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        Config c = this.getConfig();
        c.setAddAlpnExtension(true);

        List<AlpnEntry> alpnEntries = new ArrayList<>();
        for (CipherSuite i : Arrays.stream(CipherSuite.values()).filter(CipherSuite::isGrease).collect(Collectors.toList())) {
            alpnEntries.add(new AlpnEntry(i.getByteValue()));
        }

        runner.setStateModifier(i -> {
            ClientHelloMessage msg = i.getWorkflowTrace().getFirstSendMessage(ClientHelloMessage.class);
            AlpnExtensionMessage ext = msg.getExtension(AlpnExtensionMessage.class);
            ext.setAlpnEntryList(alpnEntries);
            return null;
        });

        runner.execute(workflowTrace, c).validateFinal(i -> {
            Validator.executedAsPlanned(i);

            ServerHelloMessage msg = i.getWorkflowTrace().getFirstReceivedMessage(ServerHelloMessage.class);
            AlpnExtensionMessage ext = msg.getExtension(AlpnExtensionMessage.class);
            if (ext == null) return;

            assertEquals("AlpnEntryExtension contains more or less than one protocol", 1, ext.getAlpnEntryList().size());
            assertFalse("Server negotiated GREASE ALPN identifier", CipherSuite.getCipherSuite(ext.getAlpnEntryList().get(0).getAlpnEntryConfig()).isGrease());
        });
    }



}
