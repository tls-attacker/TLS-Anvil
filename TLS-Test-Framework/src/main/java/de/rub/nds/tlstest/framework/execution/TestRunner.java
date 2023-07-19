/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.execution;

import static org.junit.platform.engine.discovery.DiscoverySelectors.selectPackage;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.rub.nds.anvilcore.context.AnvilContext;
import de.rub.nds.anvilcore.context.AnvilFactoryRegistry;
import de.rub.nds.scanner.core.constants.ProbeType;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.task.StateExecutionTask;
import de.rub.nds.tlsattacker.transport.Connection;
import de.rub.nds.tlsattacker.transport.tcp.ServerTcpTransportHandler;
import de.rub.nds.tlsscanner.clientscanner.config.ClientScannerConfig;
import de.rub.nds.tlsscanner.clientscanner.execution.TlsClientScanner;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.serverscanner.config.ServerScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.execution.TlsServerScanner;
import de.rub.nds.tlstest.framework.ClientFeatureExtractionResult;
import de.rub.nds.tlstest.framework.FeatureExtractionResult;
import de.rub.nds.tlstest.framework.ServerFeatureExtractionResult;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.anvil.TlsContextDelegate;
import de.rub.nds.tlstest.framework.anvil.TlsModelType;
import de.rub.nds.tlstest.framework.anvil.TlsParameterFactory;
import de.rub.nds.tlstest.framework.anvil.TlsParameterIdentifierProvider;
import de.rub.nds.tlstest.framework.config.TestConfig;
import de.rub.nds.tlstest.framework.config.delegates.ConfigDelegates;
import de.rub.nds.tlstest.framework.config.delegates.TestClientDelegate;
import de.rub.nds.tlstest.framework.constants.TestEndpointType;
import de.rub.nds.tlstest.framework.extractor.TestCaseExtractor;
import de.rub.nds.tlstest.framework.model.TlsParameterType;
import de.rub.nds.tlstest.framework.reporting.ExecutionListener;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InvalidClassException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;
import java.util.stream.Collectors;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.platform.engine.TestSource;
import org.junit.platform.engine.TestTag;
import org.junit.platform.engine.support.descriptor.MethodSource;
import org.junit.platform.launcher.Launcher;
import org.junit.platform.launcher.LauncherDiscoveryRequest;
import org.junit.platform.launcher.TagFilter;
import org.junit.platform.launcher.TestIdentifier;
import org.junit.platform.launcher.TestPlan;
import org.junit.platform.launcher.core.LauncherConfig;
import org.junit.platform.launcher.core.LauncherDiscoveryRequestBuilder;
import org.junit.platform.launcher.core.LauncherFactory;
import org.junit.platform.launcher.listeners.SummaryGeneratingListener;
import org.junit.platform.launcher.listeners.TestExecutionSummary;

/**
 * This class sets up and starts JUnit to execute the tests, when the runTests function is called.
 * Before the tests are started, the preparation phase is executed.
 */
public class TestRunner {
    private static final Logger LOGGER = LogManager.getLogger();

    private final TestConfig testConfig;
    private final TestContext testContext;
    private Process tcpdumpProcess;

    private boolean targetIsReady = false;

    public TestRunner(TestConfig testConfig, TestContext testContext) {
        this.testConfig = testConfig;
        this.testContext = testContext;
    }

    private void saveToCache(@Nonnull FeatureExtractionResult report) {
        String fileName;
        if (testConfig.getTestEndpointMode() == TestEndpointType.CLIENT) {
            fileName = testConfig.getTestClientDelegate().getPort().toString();
        } else {
            fileName = testConfig.getTestServerDelegate().getHost();
        }

        try {
            ObjectMapper mapper = new ObjectMapper();
            mapper.setVisibility(mapper.getSerializationConfig().getDefaultVisibilityChecker());
            mapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);

            mapper.writeValue(new File(fileName + ".json"), report);

            FileOutputStream fos = new FileOutputStream(fileName);
            ObjectOutputStream oos = new ObjectOutputStream(fos);
            oos.writeObject(report);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Nullable
    private FeatureExtractionResult loadFromCache() {
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
                LOGGER.info("Reading cached ScanReport");
                return (FeatureExtractionResult) ois.readObject();
            } catch (InvalidClassException e) {
                LOGGER.info("Cached SiteReport appears to be outdated");
            } catch (Exception e) {
                LOGGER.error("Failed to load cached ScanReport");
            }
        }

        return null;
    }

    private void waitForClient() {
        try {
            new Thread(
                            () -> {
                                while (!targetIsReady) {
                                    LOGGER.info("Waiting for the client to get ready...");
                                    try {
                                        State state = new State();
                                        testConfig
                                                .getTestClientDelegate()
                                                .executeTriggerScript(state);
                                    } catch (Exception ignored) {
                                    }

                                    try {
                                        Thread.sleep(1000);
                                    } catch (Exception ignored) {
                                    }
                                }
                            })
                    .start();
            Socket socket = testConfig.getTestClientDelegate().getServerSocket().accept();
            targetIsReady = true;
            socket.close();
        } catch (Exception ignored) {
        }

        LOGGER.info("Client is ready, prepapring client exploration...");
    }

    private void waitForServer() {
        OutboundConnection connection = testConfig.createConfig().getDefaultClientConnection();

        try {
            Socket conTest = null;
            while (!targetIsReady) {
                try {
                    String connectionEndpoint;
                    if (connection.getHostname() != null) {
                        connectionEndpoint = connection.getHostname();
                    } else {
                        connectionEndpoint = connection.getIp();
                    }
                    conTest = new Socket(connectionEndpoint, connection.getPort());
                    targetIsReady = conTest.isConnected();
                } catch (Exception e) {
                    LOGGER.warn("Server not yet available (" + e.getLocalizedMessage() + ")");
                    Thread.sleep(1000);
                }
            }
            conTest.close();
        } catch (Exception e) {
            LOGGER.error(e);
            System.exit(2);
        }
    }

    private void serverTestPreparation() {
        waitForServer();

        FeatureExtractionResult cachedReport = loadFromCache();
        if (cachedReport != null) {
            testContext.setFeatureExtractionResult(cachedReport);
            return;
        }

        LOGGER.info("Server available, starting TLS-Scanner");
        ServerScannerConfig scannerConfig =
                new ServerScannerConfig(
                        testConfig.getGeneralDelegate(), testConfig.getTestServerDelegate());
        scannerConfig.setTimeout(testConfig.getConnectionTimeout());
        Config config = scannerConfig.createConfig();
        config.setAddServerNameIndicationExtension(
                testConfig.createConfig().isAddServerNameIndicationExtension());
        config.getDefaultClientConnection().setConnectionTimeout(0);

        scannerConfig
                .getExecutorConfig()
                .setProbes(
                        TlsProbeType.COMMON_BUGS,
                        TlsProbeType.CIPHER_SUITE,
                        TlsProbeType.CERTIFICATE,
                        TlsProbeType.COMPRESSIONS,
                        TlsProbeType.NAMED_GROUPS,
                        TlsProbeType.PROTOCOL_VERSION,
                        TlsProbeType.EC_POINT_FORMAT,
                        TlsProbeType.RESUMPTION,
                        TlsProbeType.EXTENSIONS,
                        TlsProbeType.RECORD_FRAGMENTATION,
                        TlsProbeType.HELLO_RETRY,
                        TlsProbeType.HTTP_HEADER,
                        TlsProbeType.CONNECTION_CLOSING_DELTA,
                        TlsProbeType.SIGNATURE_AND_HASH);
        scannerConfig.getExecutorConfig().setOverallThreads(1);
        scannerConfig.getExecutorConfig().setParallelProbes(1);
        scannerConfig.setConfigSearchCooldown(true);

        TlsServerScanner scanner =
                new TlsServerScanner(scannerConfig, testContext.getStateExecutor());

        FeatureExtractionResult report =
                ServerFeatureExtractionResult.fromServerScanReport(scanner.scan());
        saveToCache(report);

        testContext.setFeatureExtractionResult(report);
        LOGGER.debug("TLS-Scanner finished!");
    }

    private void clientTestPreparation() {
        waitForClient();

        ClientFeatureExtractionResult cachedReport =
                (ClientFeatureExtractionResult) loadFromCache();
        if (cachedReport != null) {
            testContext.setFeatureExtractionResult(cachedReport);
            testContext.setReceivedClientHelloMessage(cachedReport.getReceivedClientHello());
            return;
        }

        ParallelExecutor preparedExecutor =
                new ParallelExecutor(testConfig.getParallelHandshakes(), 2);
        preparedExecutor.setDefaultBeforeTransportPreInitCallback(getSocketManagementCallback());

        ClientHelloMessage clientHello = catchClientHello(preparedExecutor);
        if (clientHello == null) {
            throw new RuntimeException("Failed to receive a ClientHello in test preparation");
        }
        LOGGER.info("Received Client Hello. Starting Client-Scanner for feature extraction.");

        ClientScannerConfig clientScannerConfig = new ClientScannerConfig(new GeneralDelegate());
        List<ProbeType> probes = new LinkedList<>();
        probes.add(TlsProbeType.BASIC);
        probes.add(TlsProbeType.CIPHER_SUITE);
        probes.add(TlsProbeType.PROTOCOL_VERSION);
        probes.add(TlsProbeType.NAMED_GROUPS);
        probes.add(TlsProbeType.RECORD_FRAGMENTATION);
        probes.add(TlsProbeType.EC_POINT_FORMAT);
        probes.add(TlsProbeType.SERVER_CERTIFICATE_MINIMUM_KEY_SIZE);
        probes.add(TlsProbeType.CONNECTION_CLOSING_DELTA);
        clientScannerConfig
                .getServerDelegate()
                .setPort(testConfig.getDelegate(TestClientDelegate.class).getPort());
        clientScannerConfig.setTimeout(testConfig.getConnectionTimeout());
        clientScannerConfig.getExecutorConfig().setProbes(probes);
        clientScannerConfig.setExternalRunCallback(
                testConfig.getTestClientDelegate().getTriggerScript());

        TlsClientScanner clientScanner =
                new TlsClientScanner(clientScannerConfig, preparedExecutor);

        String identifier =
                testConfig.getIdentifier() == null ? "client" : testConfig.getIdentifier();
        ClientFeatureExtractionResult extractionResult =
                ClientFeatureExtractionResult.fromClientScanReport(
                        clientScanner.scan(), identifier);

        extractionResult.setReceivedClientHello(clientHello);
        saveToCache(extractionResult);
        testContext.setReceivedClientHelloMessage(clientHello);
        testContext.setFeatureExtractionResult(extractionResult);
    }

    public StateExecutionTask buildStateExecutionServerTask(State state) throws RuntimeException {
        StateExecutionTask task = new StateExecutionTask(state, 2);
        Connection connection = state.getConfig().getDefaultServerConnection();
        try {
            state.getTlsContext()
                    .setTransportHandler(
                            new ServerTcpTransportHandler(
                                    testConfig.getConnectionTimeout(),
                                    testConfig.getConnectionTimeout(),
                                    testConfig.getTestClientDelegate().getServerSocket()));
        } catch (IOException ex) {
            throw new RuntimeException("Failed to set TransportHandler");
        }
        task.setBeforeTransportInitCallback(testConfig.getTestClientDelegate().getTriggerScript());
        return task;
    }

    private void startTcpDump() {
        if (tcpdumpProcess != null) {
            LOGGER.warn("This should not happen...");
            return;
        }

        String networkInterface = testConfig.getNetworkInterface();

        if (networkInterface.equals("any")) {
            LOGGER.warn(
                    "Tcpdump will capture on all interfaces. Use -networkInterface to reduce amount of collected data.");
        }

        ProcessBuilder tcpdump =
                new ProcessBuilder(
                        "tcpdump",
                        "-i",
                        networkInterface,
                        "-w",
                        Paths.get(testConfig.getOutputFolder(), "dump.pcap").toString());

        try {
            tcpdumpProcess = tcpdump.start();
            boolean isFinished = tcpdumpProcess.waitFor(2, TimeUnit.SECONDS);
            if (!isFinished) throw new IllegalStateException();
            String out =
                    new String(
                            tcpdumpProcess.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            out +=
                    new String(
                            tcpdumpProcess.getErrorStream().readAllBytes(), StandardCharsets.UTF_8);
            throw new RuntimeException(out);
        } catch (IllegalStateException ignored) {

        } catch (Exception e) {
            LOGGER.error("Starting tcpdump failed", e);
        }
    }

    public void prepareTestExecution() {
        if (!testConfig.isParsedArgs()) {
            return;
        }

        if (!testConfig.isDisableTcpDump()) {
            startTcpDump();
        }

        ParallelExecutor executor = new ParallelExecutor(testConfig.getParallelHandshakes(), 2);
        executor.setTimeoutAction(testConfig.getTimeoutActionScript());
        executor.armTimeoutAction(20000);
        testContext.setStateExecutor(executor);

        LOGGER.info("Starting preparation phase");
        this.testConfig.createConfig();

        if (this.testConfig.getTestEndpointMode() == TestEndpointType.CLIENT) {
            clientTestPreparation();
        } else if (this.testConfig.getTestEndpointMode() == TestEndpointType.SERVER) {
            serverTestPreparation();
        } else throw new RuntimeException("Invalid TestEndpointMode");

        if (testContext.getFeatureExtractionResult() == null) {
            throw new RuntimeException(
                    "Feature extraction result was not set after test preparation");
        }

        boolean startTestSuite = false;
        if (testContext.getFeatureExtractionResult().getSupportedVersions() == null
                || testContext.getFeatureExtractionResult().getSupportedVersions().isEmpty()) {
            LOGGER.error("Target does not support any ProtocolVersion");
        } else if (testContext.getFeatureExtractionResult().getCipherSuites().isEmpty()
                && testContext
                        .getFeatureExtractionResult()
                        .getSupportedTls13CipherSuites()
                        .isEmpty()) {
            LOGGER.error("Target does not support any CipherSuites");
        } else if (!testContext
                        .getFeatureExtractionResult()
                        .getSupportedVersions()
                        .contains(ProtocolVersion.TLS12)
                && !testContext
                        .getFeatureExtractionResult()
                        .getSupportedVersions()
                        .contains(ProtocolVersion.TLS13)) {
            LOGGER.error("Target does not support any ProtocolVersion that the Testsuite supports");
        } else {
            startTestSuite = true;
        }

        if (!startTestSuite) {
            System.exit(9);
        }

        LOGGER.info("Prepartion finished!");
    }

    private boolean countTests(TestIdentifier i, String versionS, String modeS) {
        TestSource source = i.getSource().orElse(null);
        if (!i.isTest() && (source == null || !source.getClass().equals(MethodSource.class))) {
            return false;
        }

        Set<TestTag> tags = i.getTags();
        boolean version = tags.stream().anyMatch(j -> j.getName().equals(versionS));
        boolean mode;
        if (!modeS.equals("both")) {
            mode = tags.stream().anyMatch(j -> j.getName().equals(modeS));
        } else {
            mode =
                    tags.stream().noneMatch(j -> j.getName().equals("server"))
                            && tags.stream().noneMatch(j -> j.getName().equals("client"));
        }

        return version && mode;
    }

    public void runTests(String packageName) {

        if (testConfig.getParsedCommand() == ConfigDelegates.EXTRACT_TESTS) {
            TestCaseExtractor extractor = new TestCaseExtractor(packageName);
            extractor.start();
            return;
        }

        prepareTestExecution();
        // todo - seems like this should be one method instead of two but the first does not add
        // them as knownParameters
        TlsParameterIdentifierProvider identifierProvider = new TlsParameterIdentifierProvider();
        AnvilFactoryRegistry.get().setParameterIdentifierProvider(identifierProvider);
        AnvilFactoryRegistry.get()
                .addParameterTypes(TlsParameterType.values(), new TlsParameterFactory());
        AnvilContext.getInstance().getKnownModelTypes().add(TlsModelType.CERTIFICATE);
        AnvilContext.getInstance().setApplicationSpecificContextDelegate(new TlsContextDelegate());
        AnvilContext anvilContext = AnvilContext.getInstance();

        LauncherDiscoveryRequestBuilder builder =
                LauncherDiscoveryRequestBuilder.request()
                        .selectors(selectPackage(packageName))
                        // https://junit.org/junit5/docs/current/user-guide/#writing-tests-parallel-execution
                        .configurationParameter(
                                "junit.jupiter.execution.parallel.mode.default", "same_thread")
                        .configurationParameter(
                                "junit.jupiter.execution.parallel.mode.classes.default",
                                "concurrent")
                        .configurationParameter(
                                "junit.jupiter.execution.parallel.config.strategy", "fixed")
                        .configurationParameter(
                                "junit.jupiter.execution.parallel.config.fixed.parallelism",
                                String.valueOf(testConfig.getParallelTests()));

        if (testConfig.getTags().size() > 0) {
            builder.filters(TagFilter.includeTags(testConfig.getTags()));
        }

        LauncherDiscoveryRequest request = builder.build();

        SummaryGeneratingListener listener = new SummaryGeneratingListener();
        ExecutionListener reporting = new ExecutionListener();

        Launcher launcher =
                LauncherFactory.create(
                        LauncherConfig.builder()
                                .enableTestExecutionListenerAutoRegistration(false)
                                .addTestExecutionListeners(listener)
                                .addTestExecutionListeners(reporting)
                                .build());

        TestPlan testplan = launcher.discover(request);
        long testcases =
                testplan.countTestIdentifiers(
                        i -> {
                            TestSource source = i.getSource().orElse(null);
                            return i.isTest()
                                    || (source != null
                                            && source.getClass().equals(MethodSource.class));
                        });
        long clientTls12 =
                testplan.countTestIdentifiers(i -> this.countTests(i, "tls12", "client"));
        long clientTls13 =
                testplan.countTestIdentifiers(i -> this.countTests(i, "tls13", "client"));
        long serverTls12 =
                testplan.countTestIdentifiers(i -> this.countTests(i, "tls12", "server"));
        long serverTls13 =
                testplan.countTestIdentifiers(i -> this.countTests(i, "tls13", "server"));
        long bothTls12 = testplan.countTestIdentifiers(i -> this.countTests(i, "tls12", "both"));
        long bothTls13 = testplan.countTestIdentifiers(i -> this.countTests(i, "tls13", "both"));

        LOGGER.info(
                "Server tests, TLS 1.2: {}, TLS 1.3: {}",
                serverTls12 + bothTls12,
                serverTls13 + bothTls13);
        LOGGER.info(
                "Client tests, TLS 1.2: {}, TLS 1.3: {}",
                clientTls12 + bothTls12,
                clientTls13 + bothTls13);
        LOGGER.info(
                "Testing using default strength "
                        + TestContext.getInstance().getConfig().getStrength());
        LOGGER.info(
                "Default timeout "
                        + TestContext.getInstance().getConfig().getConnectionTimeout()
                        + " ms");
        logCommonDerivationValues();
        AnvilContext.getInstance().setTotalTests(testcases);
        long start = System.currentTimeMillis();

        launcher.execute(request);

        double elapsedTime = (System.currentTimeMillis() - start) / 1000.0;
        if (elapsedTime < 10) {
            LOGGER.error("Something seems to be wrong, testsuite executed in " + elapsedTime + "s");
        }

        TestExecutionSummary summary = listener.getSummary();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        PrintWriter writer = new PrintWriter(baos, true);
        summary.printTo(writer);
        String content = new String(baos.toByteArray(), StandardCharsets.UTF_8);
        LOGGER.info("\n" + content);

        testContext.getStateExecutor().shutdown();

        try {
            testConfig.getTestClientDelegate().getServerSocket().close();
        } catch (Exception e) {
        }

        stopTcpDump();
        System.exit(0);
    }

    private void stopTcpDump() {
        if (tcpdumpProcess != null) {
            try {
                tcpdumpProcess.destroy();
            } catch (Exception ignored) {
            }
        }
    }

    private void logCommonDerivationValues() {
        LOGGER.info(
                "Supported NamedGroups:  "
                        + TestContext.getInstance()
                                .getFeatureExtractionResult()
                                .getNamedGroups()
                                .stream()
                                .map(NamedGroup::toString)
                                .collect(Collectors.joining(",")));
        LOGGER.info(
                "Supported CipherSuites: "
                        + TestContext.getInstance()
                                .getFeatureExtractionResult()
                                .getCipherSuites()
                                .stream()
                                .map(CipherSuite::toString)
                                .collect(Collectors.joining(",")));
        if (TestContext.getInstance().getFeatureExtractionResult().getTls13Groups() != null) {
            LOGGER.info(
                    "Supported TLS 1.3 NamedGroups: "
                            + TestContext.getInstance()
                                    .getFeatureExtractionResult()
                                    .getTls13Groups()
                                    .stream()
                                    .map(NamedGroup::toString)
                                    .collect(Collectors.joining(",")));
        }
        if (TestContext.getInstance().getFeatureExtractionResult().getSupportedTls13CipherSuites()
                != null) {
            LOGGER.info(
                    "Supported TLS 1.3 CipherSuites: "
                            + TestContext.getInstance()
                                    .getFeatureExtractionResult()
                                    .getSupportedTls13CipherSuites()
                                    .stream()
                                    .map(CipherSuite::toString)
                                    .collect(Collectors.joining(",")));
        }
    }

    private ClientHelloMessage catchClientHello(ParallelExecutor executor) {
        LOGGER.info("Attempting to receive a Client Hello");
        Config config = testConfig.createConfig();
        WorkflowTrace catchHelloWorkflowTrace = new WorkflowTrace();
        catchHelloWorkflowTrace.addTlsAction(new ReceiveAction(new ClientHelloMessage()));
        State catchHelloState = new State(config, catchHelloWorkflowTrace);
        StateExecutionTask catchHelloTask = new StateExecutionTask(catchHelloState, 2);
        catchHelloTask.setBeforeTransportInitCallback(
                testConfig.getTestClientDelegate().getTriggerScript());
        catchHelloTask.setBeforeTransportPreInitCallback(getSocketManagementCallback());
        executor.bulkExecuteTasks(catchHelloTask);

        return (ClientHelloMessage)
                WorkflowTraceUtil.getFirstReceivedMessage(
                        HandshakeMessageType.CLIENT_HELLO, catchHelloWorkflowTrace);
    }

    /**
     * Ensures that the ClientScanner always uses the externally managed socket
     *
     * @return Function to set socket in created state
     */
    private Function<State, Integer> getSocketManagementCallback() {
        return (State state) -> {
            try {
                state.getTlsContext()
                        .setTransportHandler(
                                new ServerTcpTransportHandler(
                                        testConfig.getConnectionTimeout(),
                                        testConfig.getConnectionTimeout(),
                                        testConfig.getTestClientDelegate().getServerSocket()));
                return 0;
            } catch (IOException ex) {
                LOGGER.error("Failed to set server socket", ex);
                return 1;
            }
        };
    }
}
