package de.rub.nds.tlstest.framework.execution;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SupportedVersionsExtensionMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.ThreadedServerWorkflowQueueExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsattacker.core.workflow.task.StateExecutionServerTask;
import de.rub.nds.tlsattacker.core.workflow.task.TlsTask;
import de.rub.nds.tlsscanner.TlsScanner;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.TestSiteReport;
import de.rub.nds.tlstest.framework.config.TestConfig;
import de.rub.nds.tlstest.framework.constants.TestEndpointType;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.platform.launcher.Launcher;
import org.junit.platform.launcher.LauncherDiscoveryRequest;
import org.junit.platform.launcher.TagFilter;
import org.junit.platform.launcher.core.LauncherDiscoveryRequestBuilder;
import org.junit.platform.launcher.core.LauncherFactory;
import org.junit.platform.launcher.listeners.SummaryGeneratingListener;
import org.junit.platform.launcher.listeners.TestExecutionSummary;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.io.*;
import java.util.*;

import static org.junit.platform.engine.discovery.DiscoverySelectors.selectPackage;

public class TestRunner {
    private static final Logger LOGGER = LogManager.getLogger();

    private final TestConfig testConfig;
    private final TestContext testContext;
    private final ParallelExecutor executor;

    public TestRunner(TestConfig testConfig, TestContext testContext) {
        this.testConfig = testConfig;
        executor = new ParallelExecutor(5, 2);
        this.testContext = testContext;
    }


    private void saveToCache(@Nonnull TestSiteReport smallReport) {
        String fileName;
        if (testConfig.getTestEndpointMode() == TestEndpointType.CLIENT) {
            fileName = testConfig.getTestClientDelegate().getPort().toString();
        } else {
            fileName = testConfig.getTestServerDelegate().getHost();
        }

        try {
            FileOutputStream fos = new FileOutputStream(fileName);
            ObjectOutputStream oos = new ObjectOutputStream(fos);
            oos.writeObject(smallReport);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Nullable
    private TestSiteReport loadFromCache() {
        String fileName;
        if (testConfig.getTestEndpointMode() == TestEndpointType.CLIENT) {
            fileName = testConfig.getTestClientDelegate().getPort().toString();
        } else {
            fileName = testConfig.getTestServerDelegate().getHost();
        }

        File f = new File(fileName);
        if (f.exists() && !testConfig.isIgnoreCache()) {
            try {
                FileInputStream fis = new FileInputStream(fileName);
                ObjectInputStream ois = new ObjectInputStream(fis);
                LOGGER.info("Using cached siteReport");
                return (TestSiteReport)ois.readObject();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        return null;
    }


    private void serverTestPreparation() {
        TestSiteReport cachedReport = loadFromCache();
        if (cachedReport != null) {
            testConfig.setSiteReport(cachedReport.getSiteReport());
            return;
        }

        ScannerConfig scannerConfig = new ScannerConfig(testConfig.getGeneralDelegate(), testConfig.getTestServerDelegate());
        int cores = Runtime.getRuntime().availableProcessors();
        scannerConfig.setOverallThreads(cores);

        TlsScanner scanner = new TlsScanner(scannerConfig);
        SiteReport report = scanner.scan();
        saveToCache(new TestSiteReport(report));

        testConfig.setSiteReport(report);
    }


    private void clientTestPreparation() {
        TestSiteReport cachedReport = loadFromCache();
        if (cachedReport != null) {
            testContext.setReceivedClientHelloMessage(cachedReport.getReceivedClientHello());
            testConfig.setSiteReport(cachedReport.getSiteReport());
            return;
        }

        List<TlsTask> tasks = new ArrayList<>();
        List<State> states = new ArrayList<>();

        List<CipherSuite> cipherList = CipherSuite.getImplemented();
        //List<CipherSuite> cipherList = new ArrayList<>();
        //cipherList.add(CipherSuite.TLS_AES_128_GCM_SHA256);

        for (CipherSuite i: cipherList) {
            Config config = this.testConfig.createConfig();
            config.setDefaultServerSupportedCiphersuites(Collections.singletonList(i));
            config.setDefaultSelectedCipherSuite(i);
            config.setEnforceSettings(true);
            config.setWriteKeylogFile(true);

            if (i.isTLS13()) {
                config.setHighestProtocolVersion(ProtocolVersion.TLS13);
                config.setAddEllipticCurveExtension(true);
                config.setAddECPointFormatExtension(true);
                config.setAddKeyShareExtension(true);
                config.setAddSignatureAndHashAlgorithmsExtension(true);
                config.setAddSupportedVersionsExtension(true);
                config.setAddRenegotiationInfoExtension(false);
                config.setDefaultServerSupportedSignatureAndHashAlgorithms(SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA384);
            }

            try {
                WorkflowConfigurationFactory configurationFactory = new WorkflowConfigurationFactory(config);
                WorkflowTrace trace = configurationFactory.createWorkflowTrace(WorkflowTraceType.HANDSHAKE, RunningModeType.SERVER);
                State s = new State(config, trace);
                StateExecutionServerTask task = new StateExecutionServerTask(s, testConfig.getTestClientDelegate().getServerSocket(), 2);
                task.setBeforeAcceptCallback(() -> {
                    testConfig.getTestClientDelegate().executeWakeupScript();
                });
                tasks.add(task);
                states.add(s);
            }
            catch(Exception ignored) {

            }
        }


        ParallelExecutor executor = new ParallelExecutor(50, 2);
        executor.bulkExecuteTasks(tasks);

        Set<CipherSuite> tls12CipherSuites = new HashSet<>();
        Set<CipherSuite> tls13CipherSuites = new HashSet<>();
        ClientHelloMessage clientHello = null;
        for (State s: states) {
            try {
                if (s.getWorkflowTrace().executedAsPlanned()) {
                    if (clientHello == null) {
                        clientHello = s.getWorkflowTrace().getFirstReceivedMessage(ClientHelloMessage.class);
                    }
                    if (s.getTlsContext().getSelectedProtocolVersion() == ProtocolVersion.TLS12)
                        tls12CipherSuites.add(s.getConfig().getDefaultSelectedCipherSuite());
                    else if (s.getTlsContext().getSelectedProtocolVersion() == ProtocolVersion.TLS13)
                        tls13CipherSuites.add(s.getConfig().getDefaultSelectedCipherSuite());
                }

                else {
                    LOGGER.debug("Workflow failed (" + s.getConfig().getDefaultSelectedCipherSuite() + ")");
                }
            } catch (Exception e) {
                LOGGER.error(e);
                throw new RuntimeException(e);
            }
        }

        TestSiteReport report = new TestSiteReport(new SiteReport("", new ArrayList<>()));
        report.setCipherSuites(tls12CipherSuites);
        report.setSupportedTls13CipherSuites(new ArrayList<>(tls13CipherSuites));
        SupportedVersionsExtensionMessage msg = clientHello.getExtension(SupportedVersionsExtensionMessage.class);
        report.setReceivedClientHello(clientHello);

        if (msg != null) {
            report.setVersions(ProtocolVersion.getProtocolVersions(msg.getSupportedVersions().getValue()));
        }

        saveToCache(report);

        testContext.setReceivedClientHelloMessage(clientHello);
        testConfig.setSiteReport(report.getSiteReport());

    }

    public void prepareTestExecution() {
        if (!testConfig.isParsedArgs()) {
            return;
        }

        LOGGER.info("Prepare Test execution - Starting TLS Scanner");
        this.testConfig.createConfig();

        if (this.testConfig.getTestEndpointMode() == TestEndpointType.CLIENT) {
            clientTestPreparation();
        }
        else if (this.testConfig.getTestEndpointMode() == TestEndpointType.SERVER) {
            serverTestPreparation();
        }
        else throw new RuntimeException("Invalid TestEndpointMode");
    }


    public void runTests(Class<?> mainClass) {
        prepareTestExecution();

        String packageName = mainClass.getPackage().getName();
        LauncherDiscoveryRequestBuilder builder = LauncherDiscoveryRequestBuilder.request()
            .selectors(
                    selectPackage(packageName)
            );


        if (testConfig.getTags().size() > 0) {
            builder.filters(
                    TagFilter.includeTags(testConfig.getTags())
            );
        }

        LauncherDiscoveryRequest request = builder.build();

        Launcher launcher = LauncherFactory.create();

        SummaryGeneratingListener listener = new SummaryGeneratingListener();
        launcher.registerTestExecutionListeners(listener);

        launcher.execute(request);

        TestExecutionSummary summary = listener.getSummary();
        summary.printTo(new PrintWriter(System.out));
    }

    public ParallelExecutor getExecutor() {
        return executor;
    }
}
