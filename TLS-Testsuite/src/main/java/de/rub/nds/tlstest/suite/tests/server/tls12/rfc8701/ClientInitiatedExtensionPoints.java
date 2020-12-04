/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
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
import de.rub.nds.tlstest.framework.annotations.ScopeExtensions;
import de.rub.nds.tlstest.framework.annotations.ServerTest;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.annotations.categories.Interoperability;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.AnnotatedStateContainer;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.DerivationType;
import de.rub.nds.tlstest.framework.model.derivationParameter.CipherSuiteDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.GreaseExtensionDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.GreaseSigHashDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.NamedGroupDerivation;
import de.rub.nds.tlstest.framework.testClasses.Tls12Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@ServerTest
@RFC(number = 8701, section = "3. Client-Initiated Extension Points")
public class ClientInitiatedExtensionPoints extends Tls12Test {

    @TlsTest(description = "A client MAY select one or more GREASE cipher suite values and advertise them in the \"cipher_suites\" field." +
            "Servers MUST NOT negotiate any GREASE value when offered in a ClientHello.")
    @Interoperability(SeverityLevel.HIGH)
    public void advertiseGreaseCiphersuites(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        
        CipherSuite selectedCipherSuite = derivationContainer.getDerivation(CipherSuiteDerivation.class).getSelectedValue();
        List<CipherSuite> cipherSuites = new LinkedList<>();
        cipherSuites.add(selectedCipherSuite);
        cipherSuites.addAll(Arrays.stream(CipherSuite.values()).filter(CipherSuite::isGrease).collect(Collectors.toList()));
        c.setDefaultClientSupportedCipherSuites(cipherSuites);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        runner.execute(workflowTrace, c).validateFinal(i -> {
            Validator.executedAsPlanned(i);

            assertEquals("Server selected wrong ciphersuite", selectedCipherSuite, i.getState().getTlsContext().getSelectedCipherSuite());
        });
    }

    @TlsTest(description = "A client MAY select one or more GREASE extension values and advertise them as extensions with varying length and contents." +
            "Servers MUST NOT negotiate any GREASE value when offered in a ClientHello.")
    @Interoperability(SeverityLevel.HIGH)
    @ScopeExtensions(DerivationType.GREASE_EXTENSION)
    public void advertiseGreaseExtensions(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        ExtensionType greaseExtension = derivationContainer.getDerivation(GreaseExtensionDerivation.class).getSelectedValue();
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);

        ClientHelloMessage ch = workflowTrace.getFirstSendMessage(ClientHelloMessage.class);
        ch.addExtension(new GreaseExtensionMessage(greaseExtension, 25));

        runner.execute(workflowTrace, c).validateFinal(i -> {
            Validator.executedAsPlanned(i);

            i.getState().getTlsContext().getNegotiatedExtensionSet().forEach(j -> {
                assertFalse("Server negotiated GREASE extension", j.name().startsWith("GREASE"));
            });
        });
    }

    @TlsTest(description = "A client MAY select one or more GREASE named group values and advertise them in the \"supported_groups\" extension, " +
            "if sent. It MAY also send KeyShareEntry values for a subset of those selected in the \"key_share\" extension. " +
            "For each of these, the \"key_exchange\" ﬁeld MAY be any value. " +
            "Servers MUST NOT negotiate any GREASE value when offered in a ClientHello.")
    @Interoperability(SeverityLevel.HIGH)
    public void advertiseGreaseNamedGroup(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);

        NamedGroup selectedGroup = derivationContainer.getDerivation(NamedGroupDerivation.class).getSelectedValue();
        List<NamedGroup> groups = Arrays.stream(NamedGroup.values()).filter(i -> i.isGrease() || i == selectedGroup).collect(Collectors.toList());
        c.setDefaultClientNamedGroups(groups);

        runner.execute(workflowTrace, c).validateFinal(Validator::executedAsPlanned);
    }


    @TlsTest(description = "A client MAY select one or more GREASE signature algorithm values " +
            "and advertise them in the \"signature_algorithms\" or " +
            "\"signature_algorithms_cert\" extensions, if sent. " +
            "Servers MUST NOT negotiate any GREASE value when offered in a ClientHello.")
    @Interoperability(SeverityLevel.HIGH)
    @ScopeExtensions(DerivationType.GREASE_SIG_HASH)
    public void advertiseGreaseSignatureAlgorithms(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        SignatureAndHashAlgorithm greaseSigHash = derivationContainer.getDerivation(GreaseSigHashDerivation.class).getSelectedValue();
        
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);

        c.getDefaultClientSupportedSignatureAndHashAlgorithms().add(greaseSigHash);


        runner.execute(workflowTrace, c).validateFinal(i -> {
            Validator.executedAsPlanned(i);

            ServerKeyExchangeMessage skx = i.getWorkflowTrace().getFirstReceivedMessage(ServerKeyExchangeMessage.class);
            if (skx == null) return;
            assertFalse("Server selected GREASE signature and hash algorithm", SignatureAndHashAlgorithm.getSignatureAndHashAlgorithm(skx.getSignatureAndHashAlgorithm().getValue()).isGrease());
        });
    }

    @TlsTest(description = "A client MAY select one or more GREASE ALPN identiﬁers " +
            "and advertise them in the \"application_layer_protocol_negotiation\" extension, if sent. " +
            "Servers MUST NOT negotiate any GREASE value when offered in a ClientHello.")
    @Interoperability(SeverityLevel.HIGH)
    public void advertiseGreaseALPNIdentifiers(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        c.setAddAlpnExtension(true);
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        
        List<AlpnEntry> alpnEntries = new ArrayList<>();
        for (CipherSuite i : Arrays.stream(CipherSuite.values()).filter(CipherSuite::isGrease).collect(Collectors.toList())) {
            alpnEntries.add(new AlpnEntry(i.name()));
        }

        ClientHelloMessage msg = workflowTrace.getFirstSendMessage(ClientHelloMessage.class);
        AlpnExtensionMessage ext = msg.getExtension(AlpnExtensionMessage.class);
        ext.setAlpnEntryList(alpnEntries);


        runner.execute(workflowTrace, c).validateFinal(i -> {
            Validator.executedAsPlanned(i);

            ServerHelloMessage smsg = i.getWorkflowTrace().getFirstReceivedMessage(ServerHelloMessage.class);
            AlpnExtensionMessage aext = smsg.getExtension(AlpnExtensionMessage.class);
            if (aext == null) return;

            assertEquals("AlpnEntryExtension contains more or less than one protocol", 1, aext.getAlpnEntryList().size());
            assertFalse("Server negotiated GREASE ALPN identifier", aext.getAlpnEntryList().get(0).getAlpnEntryConfig().contains("GREASE"));
        });
    }



}
