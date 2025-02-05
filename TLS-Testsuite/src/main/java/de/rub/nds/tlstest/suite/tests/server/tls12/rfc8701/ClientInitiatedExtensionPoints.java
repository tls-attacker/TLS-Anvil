/**
 * TLS-Testsuite - A testsuite for the TLS protocol
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.suite.tests.server.tls12.rfc8701;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

import de.rub.nds.anvilcore.annotation.*;
import de.rub.nds.anvilcore.teststate.AnvilTestCase;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.AlpnExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.GreaseExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.alpn.AlpnEntry;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceConfigurationUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlstest.framework.Validator;
import de.rub.nds.tlstest.framework.execution.WorkflowRunner;
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

@ServerTest
public class ClientInitiatedExtensionPoints extends Tls12Test {

    @AnvilTest(id = "8701-E4jT9RDD5y")
    @ExcludeParameters({
        @ExcludeParameter("INCLUDE_GREASE_CIPHER_SUITES"),
        @ExcludeParameter("INCLUDE_GREASE_NAMED_GROUPS"),
        @ExcludeParameter("INCLUDE_GREASE_SIG_HASH_ALGORITHMS")
    })
    public void advertiseGreaseCiphersuites(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);

        CipherSuite selectedCipherSuite =
                parameterCombination.getParameter(CipherSuiteDerivation.class).getSelectedValue();
        List<CipherSuite> cipherSuites = new LinkedList<>();
        cipherSuites.add(selectedCipherSuite);
        cipherSuites.addAll(
                Arrays.stream(CipherSuite.values())
                        .filter(CipherSuite::isGrease)
                        .collect(Collectors.toList()));
        c.setDefaultClientSupportedCipherSuites(cipherSuites);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);
        State state = runner.execute(workflowTrace, c);

        Validator.executedAsPlanned(state, testCase);
        assertEquals(
                "Server selected wrong ciphersuite",
                selectedCipherSuite,
                state.getTlsContext().getSelectedCipherSuite());
    }

    @AnvilTest(id = "8701-7DCDj6NnBm")
    @IncludeParameter("GREASE_EXTENSION")
    @ExcludeParameters({
        @ExcludeParameter("INCLUDE_GREASE_CIPHER_SUITES"),
        @ExcludeParameter("INCLUDE_GREASE_NAMED_GROUPS"),
        @ExcludeParameter("INCLUDE_GREASE_SIG_HASH_ALGORITHMS")
    })
    public void advertiseGreaseExtensions(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);
        ExtensionType greaseExtension =
                parameterCombination
                        .getParameter(GreaseExtensionDerivation.class)
                        .getSelectedValue();
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);

        ClientHelloMessage ch =
                (ClientHelloMessage)
                        WorkflowTraceConfigurationUtil.getFirstStaticConfiguredSendMessage(
                                workflowTrace, HandshakeMessageType.CLIENT_HELLO);
        ch.addExtension(new GreaseExtensionMessage(greaseExtension, 25));

        State state = runner.execute(workflowTrace, c);

        Validator.executedAsPlanned(state, testCase);

        state.getTlsContext()
                .getNegotiatedExtensionSet()
                .forEach(
                        j -> {
                            assertFalse(
                                    "Server negotiated GREASE extension",
                                    j.name().startsWith("GREASE"));
                        });
    }

    @AnvilTest(id = "8701-BAMcGFuNFr")
    @ExcludeParameters({
        @ExcludeParameter("INCLUDE_GREASE_CIPHER_SUITES"),
        @ExcludeParameter("INCLUDE_GREASE_NAMED_GROUPS"),
        @ExcludeParameter("INCLUDE_GREASE_SIG_HASH_ALGORITHMS")
    })
    public void advertiseGreaseNamedGroup(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);

        NamedGroup selectedGroup =
                parameterCombination.getParameter(NamedGroupDerivation.class).getSelectedValue();
        List<NamedGroup> groups =
                Arrays.stream(NamedGroup.values())
                        .filter(i -> i.isGrease() || i == selectedGroup)
                        .collect(Collectors.toList());
        c.setDefaultClientNamedGroups(groups);

        State state = runner.execute(workflowTrace, c);
        Validator.executedAsPlanned(state, testCase);
    }

    @AnvilTest(id = "8701-ngetVmJySH")
    @IncludeParameter("GREASE_SIG_HASH")
    @ExcludeParameters({
        @ExcludeParameter("INCLUDE_GREASE_CIPHER_SUITES"),
        @ExcludeParameter("INCLUDE_GREASE_NAMED_GROUPS"),
        @ExcludeParameter("INCLUDE_GREASE_SIG_HASH_ALGORITHMS")
    })
    public void advertiseGreaseSignatureAlgorithms(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);
        SignatureAndHashAlgorithm greaseSigHash =
                parameterCombination.getParameter(GreaseSigHashDerivation.class).getSelectedValue();

        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);

        c.getDefaultClientSupportedSignatureAndHashAlgorithms().add(greaseSigHash);

        State state = runner.execute(workflowTrace, c);

        Validator.executedAsPlanned(state, testCase);

        ServerKeyExchangeMessage skx =
                state.getWorkflowTrace().getFirstReceivedMessage(ServerKeyExchangeMessage.class);
        if (skx == null) {
            return;
        }
        assertFalse(
                "Server selected GREASE signature and hash algorithm",
                SignatureAndHashAlgorithm.getSignatureAndHashAlgorithm(
                                skx.getSignatureAndHashAlgorithm().getValue())
                        .isGrease());
    }

    @AnvilTest(id = "8701-SCkMwRniGX")
    @ExcludeParameters({
        @ExcludeParameter("INCLUDE_GREASE_CIPHER_SUITES"),
        @ExcludeParameter("INCLUDE_GREASE_NAMED_GROUPS"),
        @ExcludeParameter("INCLUDE_GREASE_SIG_HASH_ALGORITHMS")
    })
    public void advertiseGreaseALPNIdentifiers(AnvilTestCase testCase, WorkflowRunner runner) {
        Config c = getPreparedConfig(runner);
        c.setAddAlpnExtension(true);
        WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HELLO);

        List<AlpnEntry> alpnEntries = new ArrayList<>();
        for (CipherSuite i :
                Arrays.stream(CipherSuite.values())
                        .filter(CipherSuite::isGrease)
                        .collect(Collectors.toList())) {
            alpnEntries.add(new AlpnEntry(i.name()));
        }

        ClientHelloMessage msg =
                (ClientHelloMessage)
                        WorkflowTraceConfigurationUtil.getFirstStaticConfiguredSendMessage(
                                workflowTrace, HandshakeMessageType.CLIENT_HELLO);
        AlpnExtensionMessage ext = msg.getExtension(AlpnExtensionMessage.class);
        ext.setAlpnEntryList(alpnEntries);

        State state = runner.execute(workflowTrace, c);

        Validator.executedAsPlanned(state, testCase);

        ServerHelloMessage smsg =
                state.getWorkflowTrace().getFirstReceivedMessage(ServerHelloMessage.class);
        AlpnExtensionMessage aext = smsg.getExtension(AlpnExtensionMessage.class);
        if (aext == null) {
            return;
        }

        assertEquals(
                "AlpnEntryExtension contains more or less than one protocol",
                1,
                aext.getAlpnEntryList().size());
        assertFalse(
                "Server negotiated GREASE ALPN identifier",
                aext.getAlpnEntryList().get(0).getAlpnEntryConfig().contains("GREASE"));
    }
}
