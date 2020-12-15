/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.DefaultWorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

import java.net.URL;
import java.security.Security;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.TimeZone;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class TestRunnerTest {

    @Test
    public void test_clientPreparation() {
        TestContext context = new TestContext();

        URL scriptPath = TestRunnerTest.class.getClassLoader().getResource("trigger.sh");
        String path = scriptPath.toString().replaceAll("^file:", "");

        context.getConfig().parse(new String[]{"-keylogfile", "/Users/philipp/", "client", "-port", "443", "-script", path});
        context.getTestRunner().prepareTestExecution();

        assertEquals("No ciphersuites supported",27, context.getSiteReport().getCipherSuites().size());
        assertEquals("No ciphersuites supported",3, context.getSiteReport().getSupportedTls13CipherSuites().size());

    }

    @Test
    public void test() {
        Config config = Config.createConfig();
        config.setDefaultClientSupportedCipherSuites(new ArrayList<>());

        Config copy = config.createCopy();
        assert copy.getDefaultClientSupportedCipherSuites().size() == config.getDefaultClientSupportedCipherSuites().size();
    }


    @Test
    public void test_TLS13_Server() {
        Security.addProvider(new BouncyCastleProvider());
        Config config = Config.createConfig();
        config.setHighestProtocolVersion(ProtocolVersion.TLS13);
        config.setSupportedVersions(ProtocolVersion.TLS13);
        config.setDefaultSelectedProtocolVersion(ProtocolVersion.TLS13);
        config.setDefaultClientSupportedCipherSuites(CipherSuite.TLS_AES_128_GCM_SHA256);
        config.setDefaultSelectedCipherSuite(CipherSuite.TLS_AES_128_GCM_SHA256);
        config.setAddSupportedVersionsExtension(true);
        config.setAddKeyShareExtension(true);
        config.setAddSignatureAndHashAlgorithmsExtension(true);
        config.getDefaultClientConnection().setHostname("localhost");
        config.setDefaultClientSupportedSignatureAndHashAlgorithms(SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA256);

        WorkflowTrace trace = new WorkflowConfigurationFactory(config).createWorkflowTrace(WorkflowTraceType.HANDSHAKE, RunningModeType.CLIENT);

        DefaultWorkflowExecutor executor = new DefaultWorkflowExecutor(new State(config, trace));
        executor.executeWorkflow();
        assertTrue(trace.executedAsPlanned());
    }

    @Test
    public void tesft() {
        Date d = new Date(System.currentTimeMillis());
        SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssXXX");
        format.setTimeZone(TimeZone.getTimeZone("UTC"));
        System.out.println(format.format(d));
    }

}
