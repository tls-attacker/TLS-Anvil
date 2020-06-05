package de.rub.nds.tlstest.framework.execution;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.ThreadedServerWorkflowQueueExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceMutator;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsattacker.core.workflow.task.StateExecutionServerTask;
import de.rub.nds.tlsattacker.core.workflow.task.StateExecutionTask;
import de.rub.nds.tlsattacker.core.workflow.task.TlsTask;
import de.rub.nds.tlsscanner.TlsScanner;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.report.SiteReport;
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

import java.io.*;
import java.util.*;
import java.util.concurrent.*;

import static org.junit.platform.engine.discovery.DiscoverySelectors.selectPackage;

public class TestRunner {
    private static final Logger LOGGER = LogManager.getLogger();

    private TestConfig testConfig;
    private ParallelExecutor executor;
    private ThreadedServerWorkflowQueueExecutor server;

    public TestRunner(TestConfig testConfig) {
        this.testConfig = testConfig;
        executor = new ParallelExecutor(5, 2);
    }

    private boolean finishedPrepartion = false;


    private void serverTestPreparation() {
        File f = new File(testConfig.getTestServerDelegate().getHost());
        if (f.exists() && !testConfig.isIgnoreCache()) {
            try (FileInputStream fis = new FileInputStream(testConfig.getTestServerDelegate().getHost());
                 ObjectInputStream ois = new ObjectInputStream(fis)) {
                final TestSiteReport report = (TestSiteReport) ois.readObject ();
                testConfig.setSiteReport(report.getSiteReport());
                LOGGER.info("Using cached siteReport");
                return;
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        ScannerConfig scannerConfig = new ScannerConfig(testConfig.getGeneralDelegate(), testConfig.getTestServerDelegate());
        int cores = Runtime.getRuntime().availableProcessors();
        scannerConfig.setOverallThreads(cores);

        TlsScanner scanner = new TlsScanner(scannerConfig);
        SiteReport report = scanner.scan();
        TestSiteReport smallReport = new TestSiteReport(report);
        try (FileOutputStream fos = new FileOutputStream (testConfig.getTestServerDelegate().getHost());
             ObjectOutputStream oos = new ObjectOutputStream (fos)) {
            oos.writeObject (smallReport);
        } catch (IOException e) {
            e.printStackTrace();
        }

        testConfig.setSiteReport(report);
    }


    private void clientTestPreparation() {
        List<TlsTask> tasks = new ArrayList<>();
        List<State> states = new ArrayList<>();

        List<CipherSuite> cipherList = CipherSuite.getImplemented();
        cipherList.removeIf(i -> !i.isTLS13());
        while (cipherList.size() > 1) {
            cipherList.remove(0);
        }

        for (CipherSuite i: cipherList) {
            Config config = this.testConfig.createConfig();
            config.setDefaultServerSupportedCiphersuites(Collections.singletonList(i));
            config.setDefaultSelectedCipherSuite(i);
            config.setEnforceSettings(true);
            config.setWriteKeylogFile(true);
            config.setKeylogFilePath("/Users/philipp/");

            if (i.isTLS13()) {
                config.setHighestProtocolVersion(ProtocolVersion.TLS13);
                config.setAddEllipticCurveExtension(true);
                config.setAddECPointFormatExtension(true);
                config.setAddKeyShareExtension(true);
                config.setAddSignatureAndHashAlgorithmsExtension(true);
                config.setAddSupportedVersionsExtension(true);
                config.setAddRenegotiationInfoExtension(false);
            }

            try {
                WorkflowConfigurationFactory configurationFactory = new WorkflowConfigurationFactory(config);
                WorkflowTrace trace = configurationFactory.createWorkflowTrace(WorkflowTraceType.HANDSHAKE, RunningModeType.SERVER);
                WorkflowTraceMutator.truncateAfter(trace, HandshakeMessageType.CERTIFICATE_VERIFY);
                State s = new State(config, trace);
                StateExecutionServerTask task = new StateExecutionServerTask(s, testConfig.getTestClientDelegate().getServerSocket(), 2);
//                task.setBeforeAcceptCallback(() -> {
//                    testConfig.getTestClientDelegate().executeWakeupScript();
//                });
                tasks.add(task);
                states.add(s);
            }
            catch(Exception ignored) {

            }
        }


        ParallelExecutor executor = new ParallelExecutor(1, 2);
        executor.bulkExecuteTasks(tasks);
        finishedPrepartion = true;

        Set<CipherSuite> tls12CipherSuites = new HashSet<>();
        Set<CipherSuite> tls13CipherSuites = new HashSet<>();
        for (State s: states) {
            try {
                if (s.getWorkflowTrace().executedAsPlanned()) {
                    if (s.getConfig().getHighestProtocolVersion() == ProtocolVersion.TLS12)
                        tls12CipherSuites.add(s.getConfig().getDefaultSelectedCipherSuite());
                    else if (s.getConfig().getHighestProtocolVersion() == ProtocolVersion.TLS13)
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

        SiteReport report = new SiteReport("", new ArrayList<>());
        report.setCipherSuites(tls12CipherSuites);
        report.setSupportedTls13CipherSuites(new ArrayList<>(tls13CipherSuites));
        testConfig.setSiteReport(report);
    }

    public void prepareTestExecution() {
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
