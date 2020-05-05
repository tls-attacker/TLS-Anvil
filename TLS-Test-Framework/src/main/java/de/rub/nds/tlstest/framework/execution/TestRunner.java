package de.rub.nds.tlstest.framework.execution;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ThreadedServerWorkflowQueueExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
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
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

import static org.junit.platform.engine.discovery.DiscoverySelectors.selectPackage;

public class TestRunner {
    private static final Logger LOGGER = LogManager.getLogger();

    private TestConfig testConfig;
    private ThreadedServerWorkflowQueueExecutor server;

    public TestRunner(TestConfig testConfig) {
        this.testConfig = testConfig;
    }

    private boolean finishedPrepartion = false;


    private void serverTestPreparation() {
        File f = new File(testConfig.getTestServerDelegate().getHost());
        if (f.exists() && !testConfig.isIgnoreCache()) {
            try (FileInputStream fis = new FileInputStream (testConfig.getTestServerDelegate().getHost());
                 ObjectInputStream ois = new ObjectInputStream (fis)) {
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
        server = new ThreadedServerWorkflowQueueExecutor(testConfig.getTestClientDelegate().getPort());
        server.startServer();

        List<CompletableFuture<State>> futures = new ArrayList<>();

        List<CipherSuite> cipherList = CipherSuite.getImplemented();

        for (CipherSuite i: cipherList) {
            Config config = this.testConfig.createConfig();
            config.setDefaultServerSupportedCiphersuites(Collections.singletonList(i));
            config.setDefaultSelectedCipherSuite(i);

            try {
                WorkflowConfigurationFactory configurationFactory = new WorkflowConfigurationFactory(config);
                WorkflowTrace trace = configurationFactory.createWorkflowTrace(WorkflowTraceType.HANDSHAKE, RunningModeType.SERVER);
                State s = new State(config, trace);
                server.enqueueWorkflow(s);
                futures.add(s.getFinishedFuture());
            }
            catch(Exception ignored) {

            }
        }

        new Thread(() -> {
            LOGGER.debug("Wakeup script thread started");

            while (!finishedPrepartion) {
                testConfig.getTestClientDelegate().executeWakeupScript();
                try {
                    Thread.sleep(20);
                } catch (InterruptedException e) {
                    LOGGER.error(e);
                }
            }
            LOGGER.debug("Wakeup script thread finished");
        }).start();


        try {
            CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).get();
            LOGGER.info("completed");
        } catch(Exception e) {
            LOGGER.info("completed");
        }
        finishedPrepartion = true;


        Set<CipherSuite> cipherSet = new HashSet<>();

        for (CompletableFuture<State> i: futures) {
            try {
                State s = i.get(10, TimeUnit.MILLISECONDS);
                if (s != null && s.getWorkflowTrace().executedAsPlanned()) {
                    cipherSet.add(s.getConfig().getDefaultSelectedCipherSuite());
                }
            } catch (InterruptedException | ExecutionException | CancellationException e) {
                //noinspection UnnecessaryContinue
                continue;
            } catch(Exception f) {
                LOGGER.error("Main thread crashed", f);
            }
        }

        SiteReport report = new SiteReport("", new ArrayList<>());
        report.setCipherSuites(cipherSet);
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
}
