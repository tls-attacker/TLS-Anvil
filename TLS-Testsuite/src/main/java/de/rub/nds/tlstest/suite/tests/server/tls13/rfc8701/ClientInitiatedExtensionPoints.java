/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.server.tls13.rfc8701;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.crypto.ec.CurveFactory;
import de.rub.nds.tlsattacker.core.crypto.ec.EllipticCurve;
import de.rub.nds.tlsattacker.core.crypto.ec.Point;
import de.rub.nds.tlsattacker.core.crypto.ec.PointFormatter;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.EncryptedExtensionsMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.AlpnExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.GreaseExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.alpn.AlpnEntry;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareEntry;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareStoreEntry;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.annotations.RFC;
import de.rub.nds.tlstest.framework.annotations.ScopeExtensions;
import de.rub.nds.tlstest.framework.annotations.ServerTest;
import de.rub.nds.tlstest.framework.annotations.TlsTest;
import de.rub.nds.tlstest.framework.constants.SeverityLevel;
import de.rub.nds.tlstest.framework.execution.AnnotatedStateContainer;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
import de.rub.nds.tlstest.framework.model.DerivationType;
import de.rub.nds.tlstest.framework.model.derivationParameter.GreaseCipherSuiteDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.GreaseExtensionDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.GreaseNamedGroupDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.GreaseSigHashDerivation;
import de.rub.nds.tlstest.framework.model.derivationParameter.NamedGroupDerivation;
import de.rub.nds.tlstest.framework.testClasses.Tls13Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

@ServerTest
@RFC(number = 8701, section = "3. Client-Initiated Extension Points")
public class ClientInitiatedExtensionPoints extends Tls13Test {

    @TlsTest(description = "A client MAY select one or more GREASE cipher suite values and advertise them in the \"cipher_suites\" field." +
            "Servers MUST NOT negotiate any GREASE value when offered in a ClientHello.", interoperabilitySeverity = SeverityLevel.CRITICAL)
    @ScopeExtensions(DerivationType.GREASE_CIPHERSUITE)
    public void advertiseGreaseCiphersuites(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        CipherSuite selectedGrease = derivationContainer.getDerivation(GreaseCipherSuiteDerivation.class).getSelectedValue();
        
        c.getDefaultClientSupportedCiphersuites().add(0, selectedGrease);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        runner.execute(workflowTrace, c).validateFinal(i -> {
            Validator.executedAsPlanned(i);

            assertEquals("Server selected wrong ciphersuite", c.getDefaultSelectedCipherSuite(), i.getState().getTlsContext().getSelectedCipherSuite());
        });
    }

    @TlsTest(description = "A client MAY select one or more GREASE extension values and advertise them as extensions with varying length and contents." +
            "Servers MUST NOT negotiate any GREASE value when offered in a ClientHello.", interoperabilitySeverity = SeverityLevel.CRITICAL)
    @ScopeExtensions(DerivationType.GREASE_EXTENSION)
    public void advertiseGreaseExtensions(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        ExtensionType selectedGrease = derivationContainer.getDerivation(GreaseExtensionDerivation.class).getSelectedValue();

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);

        ClientHelloMessage ch = workflowTrace.getFirstSendMessage(ClientHelloMessage.class);
        ch.addExtension(new GreaseExtensionMessage(selectedGrease, 25));

        runner.execute(workflowTrace, c).validateFinal(i -> {
            Validator.executedAsPlanned(i);

            ServerHelloMessage msg = i.getWorkflowTrace().getFirstReceivedMessage(ServerHelloMessage.class);
            i.getState().getTlsContext().getNegotiatedExtensionSet().forEach(j -> {
                assertFalse("Server negotiated GREASE extension", j.name().startsWith("GREASE"));
            });
        });
    }

    @TlsTest(description = "A client MAY select one or more GREASE named group values and advertise them in the \"supported_groups\" extension, " +
            "if sent. It MAY also send KeyShareEntry values for a subset of those selected in the \"key_share\" extension. " +
            "For each of these, the \"key_exchange\" ﬁeld MAY be any value. " +
            "Servers MUST NOT negotiate any GREASE value when offered in a ClientHello.", interoperabilitySeverity = SeverityLevel.CRITICAL)
    @ScopeExtensions(DerivationType.GREASE_NAMED_GROUP)
    public void advertiseGreaseNamedGroup(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        NamedGroup selectedGrease = derivationContainer.getDerivation(GreaseNamedGroupDerivation.class).getSelectedValue();
        NamedGroup actualGroup = derivationContainer.getDerivation(NamedGroupDerivation.class).getSelectedValue();
        
        c.getDefaultClientNamedGroups().add(0, selectedGrease);
        //add actual NamedGroup second time to obtain dummy entry
        c.getDefaultClientKeyShareNamedGroups().add(actualGroup);
        
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        
        List <KeyShareEntry> ks = workflowTrace.getFirstSendMessage(ClientHelloMessage.class).getExtension(KeyShareExtensionMessage.class).getKeyShareList();
        ks.get(0).setGroupConfig(selectedGrease);

        runner.execute(workflowTrace, c).validateFinal(i -> {
            Validator.executedAsPlanned(i);

            ServerHelloMessage msg = i.getWorkflowTrace().getFirstReceivedMessage(ServerHelloMessage.class);
            KeyShareExtensionMessage keyshares = msg.getExtension(KeyShareExtensionMessage.class);
            keyshares.getKeyShareList().forEach(j -> {
                assertFalse("Server negotiated GREASE named group", NamedGroup.getNamedGroup(j.getGroup().getValue()).isGrease());
            });

        });
    }


    @TlsTest(description = "A client MAY select one or more GREASE signature algorithm values " +
            "and advertise them in the \"signature_algorithms\" or " +
            "\"signature_algorithms_cert\" extensions, if sent. " +
            "Servers MUST NOT negotiate any GREASE value when offered in a ClientHello.", interoperabilitySeverity = SeverityLevel.CRITICAL)
    @ScopeExtensions(DerivationType.GREASE_SIG_HASH)
    public void advertiseGreaseSignatureAlgorithms(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        SignatureAndHashAlgorithm selectedGrease = derivationContainer.getDerivation(GreaseSigHashDerivation.class).getSelectedValue();
        c.getDefaultClientSupportedSignatureAndHashAlgorithms().add(0, selectedGrease);
        
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);

        runner.execute(workflowTrace, c).validateFinal(i -> {
            Validator.executedAsPlanned(i);

            CertificateVerifyMessage msg = i.getWorkflowTrace().getFirstReceivedMessage(CertificateVerifyMessage.class);
            SignatureAndHashAlgorithm selected = SignatureAndHashAlgorithm.getSignatureAndHashAlgorithm(msg.getSignatureHashAlgorithm().getValue());
            assertFalse("Server selected GREASE signature and hash algorithm", selected.isGrease());
        });
    }

    @TlsTest(description = "A client MAY select one or more GREASE ALPN identiﬁers " +
            "and advertise them in the \"application_layer_protocol_negotiation\" extension, if sent. " +
            "Servers MUST NOT negotiate any GREASE value when offered in a ClientHello.", interoperabilitySeverity = SeverityLevel.CRITICAL)
    public void advertiseGreaseALPNIdentifiers(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
        Config c = getPreparedConfig(argumentAccessor, runner);
        c.setAddAlpnExtension(true);
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        
        List<AlpnEntry> alpnEntries = new ArrayList<>();
        for (CipherSuite i : Arrays.stream(CipherSuite.values()).filter(CipherSuite::isGrease).collect(Collectors.toList())) {
            alpnEntries.add(new AlpnEntry(i.getByteValue()));
        }

        ClientHelloMessage msg = workflowTrace.getFirstSendMessage(ClientHelloMessage.class);
        AlpnExtensionMessage ext = msg.getExtension(AlpnExtensionMessage.class);
        ext.setAlpnEntryList(alpnEntries);

        runner.execute(workflowTrace, c).validateFinal(i -> {
            Validator.executedAsPlanned(i);

            EncryptedExtensionsMessage emsg = i.getWorkflowTrace().getFirstReceivedMessage(EncryptedExtensionsMessage.class);
            AlpnExtensionMessage aext = emsg.getExtension(AlpnExtensionMessage.class);
            if (aext == null) return;

            assertEquals("AlpnEntryExtension contains more or less than one protocol", 1, aext.getAlpnEntryList().size());
            assertFalse("Server negotiated GREASE ALPN Identifier", CipherSuite.getCipherSuite(ext.getAlpnEntryList().get(0).getAlpnEntryConfig()).isGrease());
        });
    }



}
