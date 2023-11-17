package de.rub.nds.tlstest.framework.execution;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import de.rub.nds.anvilcore.constants.TestEndpointType;
import de.rub.nds.anvilcore.context.AnvilContext;
import de.rub.nds.anvilcore.junit.extension.EndpointConditionExtension;
import de.rub.nds.scanner.core.guideline.GuidelineReport;
import de.rub.nds.scanner.core.probe.ProbeType;
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
import de.rub.nds.tlsattacker.transport.tcp.ServerTcpTransportHandler;
import de.rub.nds.tlsattacker.transport.udp.ServerUdpTransportHandler;
import de.rub.nds.tlsscanner.clientscanner.config.ClientScannerConfig;
import de.rub.nds.tlsscanner.clientscanner.execution.TlsClientScanner;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.serverscanner.config.ServerScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.execution.TlsServerScanner;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlstest.framework.ClientFeatureExtractionResult;
import de.rub.nds.tlstest.framework.FeatureExtractionResult;
import de.rub.nds.tlstest.framework.ServerFeatureExtractionResult;
import de.rub.nds.tlstest.framework.TestContext;
import de.rub.nds.tlstest.framework.config.TlsTestConfig;
import de.rub.nds.tlstest.framework.config.delegates.TestClientDelegate;
import de.rub.nds.tlstest.framework.junitExtensions.TlsVersionCondition;
import java.io.*;
import java.lang.reflect.Method;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashSet;
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
import org.junit.platform.engine.support.descriptor.MethodSource;
import org.junit.platform.launcher.*;

/**
 * The TestPreparator is used before a test execution. It ensures, that the server or client is
 * ready to be tested and runs a feature extraction scan.
 */
public class TestPreparator {
    private static final Logger LOGGER = LogManager.getLogger();

    private final TlsTestConfig testConfig;
    private final TestContext testContext;
    private Process tcpdumpProcess;

    private boolean targetIsReady = false;

    public TestPreparator(TlsTestConfig testConfig, TestContext testContext) {
        this.testConfig = testConfig;
        this.testContext = testContext;
    }

    /**
     * Save the supplied FeatureExtractionResult to the disk. Two files are created: a JavaObject
     * .ser and a readable .json file.
     *
     * @param report the FeatureExtractionResult created through TLS-Scanner
     */
    private void saveToCache(@Nonnull FeatureExtractionResult report) {
        String fileName;
        if (testConfig.getTestEndpointMode() == TestEndpointType.CLIENT) {
            fileName = testConfig.getTestClientDelegate().getPort().toString();
        } else {
            fileName =
                    testConfig.getTestServerDelegate().getExtractedHost()
                            + "_"
                            + testConfig.getTestServerDelegate().getExtractedPort();
        }

        try {
            ObjectMapper mapper = new ObjectMapper();
            mapper.setVisibility(mapper.getSerializationConfig().getDefaultVisibilityChecker());
            mapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);

            mapper.writeValue(new File(fileName + ".json"), report);

            FileOutputStream fos = new FileOutputStream(fileName + ".ser");
            ObjectOutputStream oos = new ObjectOutputStream(fos);
            oos.writeObject(report);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Returns a FeatureExtractionResult, if a corresponding file for the given configuration is
     * found on disk. Only the serialized Java-Object .ser file is used.
     *
     * @return the FeatureExtractionResult or null, if not found
     */
    @Nullable
    private FeatureExtractionResult loadFromCache() {
        String fileName;
        if (testConfig.getTestEndpointMode() == TestEndpointType.CLIENT) {
            fileName = testConfig.getTestClientDelegate().getPort().toString();
        } else {
            fileName =
                    testConfig.getTestServerDelegate().getExtractedHost()
                            + "_"
                            + testConfig.getTestServerDelegate().getExtractedPort()
                            + ".ser";
        }

        File f = new File(fileName);
        if (f.exists() && !testConfig.getAnvilTestConfig().isIgnoreCache()) {
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

    /**
     * Runs the client trigger script stored in the config until a client connects. Blocks until
     * success.
     */
    private void waitForClient() {
        try {
            new Thread(
                            () -> {
                                while (!targetIsReady && !testContext.isAborted()) {
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
            if (!testConfig.isUseDTLS()) {
                Socket socket = testConfig.getTestClientDelegate().getServerSocket().accept();
                targetIsReady = true;
                socket.close();
            } else {
                try {
                    DatagramSocket socket =
                            new DatagramSocket(testConfig.getTestClientDelegate().getPort());

                    byte[] buf = new byte[256];

                    while (!targetIsReady) {
                        try {
                            DatagramPacket packet = new DatagramPacket(buf, buf.length);
                            socket.receive(packet);
                            if (packet.getLength() > 0) {
                                targetIsReady = true;
                                socket.close();
                            }

                        } catch (Exception ignored) {
                            ignored.printStackTrace();
                        }
                    }
                } catch (SocketException e) {
                    throw new RuntimeException(e);
                }
            }
        } catch (Exception ex) {
            LOGGER.error(ex);
            throw new RuntimeException("Failed to await client connection");
        }

        LOGGER.info("Client is ready, preparing client exploration...");
    }

    /**
     * Tries to make a TCP handshake connection with the server host given in the config. Blocks
     * until success.
     */
    private void waitForServer() {
        OutboundConnection connection = testConfig.createConfig().getDefaultClientConnection();

        try {
            Socket conTest = null;
            DatagramSocket conTestDtls = null;
            while (!targetIsReady && !testContext.isAborted()) {
                try {
                    if (testConfig.isUseDTLS()) {
                        String connectionEndpoint;
                        if (connection.getHostname() != null) {
                            connectionEndpoint = connection.getHostname();
                        } else {
                            connectionEndpoint = connection.getIp();
                        }

                        conTestDtls = new DatagramSocket();
                        conTestDtls.connect(
                                InetAddress.getByName(connectionEndpoint), connection.getPort());
                        targetIsReady = conTestDtls.isConnected(); // TODO always true
                    } else {
                        String connectionEndpoint;
                        if (connection.getHostname() != null) {
                            connectionEndpoint = connection.getHostname();
                        } else {
                            connectionEndpoint = connection.getIp();
                        }
                        conTest = new Socket(connectionEndpoint, connection.getPort());
                        targetIsReady = conTest.isConnected();
                    }
                } catch (Exception e) {
                    LOGGER.warn("Server not yet available (" + e.getLocalizedMessage() + ")");
                    Thread.sleep(1000);
                }
            }
            if (testConfig.isUseDTLS()) {
                conTestDtls.close();
            } else {
                conTest.close();
            }
        } catch (Exception e) {
            LOGGER.error(e);
            System.exit(2);
        }
    }

    /**
     * Prepare server test execution: Waiting until the server is ready, and starting a feature
     * extraction scan if necessary.
     */
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
        scannerConfig.setTimeout(testConfig.getAnvilTestConfig().getConnectionTimeout());
        Config config = scannerConfig.createConfig();
        config.setAddServerNameIndicationExtension(
                testConfig.createConfig().isAddServerNameIndicationExtension());
        config.getDefaultClientConnection().setConnectionTimeout(0);

        if (testConfig.isUseDTLS()) {
            scannerConfig.getDtlsDelegate().setDTLS(true);
        }

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

        ServerReport serverReport = scanner.scan();
        FeatureExtractionResult report =
                ServerFeatureExtractionResult.fromServerScanReport(serverReport);
        saveGuidelines(serverReport.getGuidelineReports());
        saveToCache(report);

        testContext.setFeatureExtractionResult(report);
        LOGGER.debug("TLS-Scanner finished!");
    }

    private void saveGuidelines(List<GuidelineReport> reports) {
        List<JsonNode> guidelineList = new ArrayList<>();
        ObjectMapper mapper = new ObjectMapper();
        for (GuidelineReport report : reports) {
            JsonNode jsonGuideline = mapper.valueToTree(report);
            for (int i = 0; i < report.getAdhered().size(); i++) {
                ObjectNode node = (ObjectNode) jsonGuideline.get("passed").get(i);
                node.put("display", report.getAdhered().get(i).toString());
            }
            for (int i = 0; i < report.getViolated().size(); i++) {
                ObjectNode node = (ObjectNode) jsonGuideline.get("failed").get(i);
                node.put("display", report.getViolated().get(i).toString());
            }
            for (int i = 0; i < report.getFailedChecks().size(); i++) {
                ObjectNode node = (ObjectNode) jsonGuideline.get("uncertain").get(i);
                node.put("display", report.getFailedChecks().get(i).toString());
            }
            for (int i = 0; i < report.getConditionNotMet().size(); i++) {
                ObjectNode node = (ObjectNode) jsonGuideline.get("skipped").get(i);
                node.put("display", report.getConditionNotMet().get(i).toString());
            }
            guidelineList.add(jsonGuideline);
        }

        AnvilContext.getInstance().getMapper().saveExtraFileToPath(guidelineList, "guidelines");
    }

    /**
     * Prepare client test execution: Waiting until the client is ready and starting a feature
     * extraction scan if necessary.
     */
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
                new ParallelExecutor(testConfig.getAnvilTestConfig().getParallelTestCases(), 2);
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
        probes.add(TlsProbeType.APPLICATION_MESSAGE);
        clientScannerConfig
                .getServerDelegate()
                .setPort(testConfig.getDelegate(TestClientDelegate.class).getPort());
        clientScannerConfig.setTimeout(testConfig.getAnvilTestConfig().getConnectionTimeout());
        clientScannerConfig.getExecutorConfig().setProbes(probes);
        clientScannerConfig.setExternalRunCallback(
                testConfig.getTestClientDelegate().getTriggerScript());
        if (testConfig.isUseDTLS()) {
            clientScannerConfig.getDtlsDelegate().setDTLS(true);
        }

        TlsClientScanner clientScanner =
                new TlsClientScanner(clientScannerConfig, preparedExecutor);

        String identifier =
                testConfig.getAnvilTestConfig().getIdentifier() == null
                        ? "client"
                        : testConfig.getAnvilTestConfig().getIdentifier();
        ClientFeatureExtractionResult extractionResult =
                ClientFeatureExtractionResult.fromClientScanReport(
                        clientScanner.scan(), identifier);

        extractionResult.setReceivedClientHello(clientHello);
        saveToCache(extractionResult);
        testContext.setReceivedClientHelloMessage(clientHello);
        testContext.setFeatureExtractionResult(extractionResult);
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
     * Should be called before starting the testing phase to ensure server or client is ready and a
     * FeatureExtractionResult is set.
     *
     * @return returns true if preparation was successful, false if the test cannot be started
     */
    public boolean prepareTestExecution() {
        if (!testConfig.isParsedArgs()) {
            return false;
        }

        ParallelExecutor executor =
                new ParallelExecutor(testConfig.getAnvilTestConfig().getParallelTestCases(), 2);
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
                        .contains(ProtocolVersion.TLS13)
                && !testContext
                        .getFeatureExtractionResult()
                        .getSupportedVersions()
                        .contains(ProtocolVersion.DTLS12)) {
            LOGGER.error("Target does not support any ProtocolVersion that the Testsuite supports");
        } else {
            startTestSuite = true;
        }

        logCommonDerivationValues();

        LOGGER.info("Prepartion finished!");
        return startTestSuite;
    }

    // TODO tcp dump for every test?
    private void startTcpDump() {
        if (tcpdumpProcess != null) {
            LOGGER.warn("This should not happen...");
            return;
        }

        String networkInterface = testConfig.getAnvilTestConfig().getNetworkInterface();

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
                        Paths.get(testConfig.getAnvilTestConfig().getOutputFolder(), "dump.pcap")
                                .toString());

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
            LOGGER.error("Starting tcpdump failed", e.getMessage());
        }
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
        FeatureExtractionResult featureExtractionResult =
                TestContext.getInstance().getFeatureExtractionResult();
        LOGGER.info(
                "Supported Protocol Versions: {}",
                featureExtractionResult.getSupportedVersions().stream()
                        .map(ProtocolVersion::toString)
                        .collect(Collectors.joining(",")));
        LOGGER.info(
                "Supported (D)TLS 1.2 Named Groups: {}",
                featureExtractionResult.getNamedGroups().stream()
                        .map(NamedGroup::toString)
                        .collect(Collectors.joining(",")));
        LOGGER.info(
                "Supported (D)TLS 1.3 Named Groups: {}",
                featureExtractionResult.getTls13Groups().stream()
                        .map(NamedGroup::toString)
                        .collect(Collectors.joining(",")));
        LOGGER.info(
                "Supported (D)TLS 1.2 Cipher Suites: {}",
                featureExtractionResult.getCipherSuites().stream()
                        .map(CipherSuite::toString)
                        .collect(Collectors.joining(",")));

        LOGGER.info(
                "Supported (D)TLS 1.3 Cipher Suites: {}",
                featureExtractionResult.getSupportedTls13CipherSuites().stream()
                        .map(CipherSuite::toString)
                        .collect(Collectors.joining(",")));
    }

    /**
     * Ensures that the ClientScanner always uses the externally managed socket
     *
     * @return Function to set socket in created state
     */
    private Function<State, Integer> getSocketManagementCallback() {
        return (State state) -> {
            try {
                if (testConfig.isUseDTLS()) {
                    state.getTlsContext()
                            .setTransportHandler(
                                    new ServerUdpTransportHandler(
                                            testConfig.getAnvilTestConfig().getConnectionTimeout(),
                                            testConfig.getAnvilTestConfig().getConnectionTimeout(),
                                            testConfig.getTestClientDelegate().getPort()));
                } else {
                    state.getTlsContext()
                            .setTransportHandler(
                                    new ServerTcpTransportHandler(
                                            testConfig.getAnvilTestConfig().getConnectionTimeout(),
                                            testConfig.getAnvilTestConfig().getConnectionTimeout(),
                                            testConfig.getTestClientDelegate().getServerSocket()));
                }
                return 0;
            } catch (IOException ex) {
                LOGGER.error("Failed to set server socket", ex);
                return 1;
            }
        };
    }

    private static boolean countTests(
            TestIdentifier i,
            ProtocolVersion versionToCount,
            TestEndpointType endpointTypeToCount,
            TestEndpointType executionTestEndpointType) {
        TestSource source = i.getSource().orElse(null);
        if (!i.isTest() && (source == null || !source.getClass().equals(MethodSource.class))) {
            return false;
        }

        MethodSource methodSource = (MethodSource) source;
        Class<?> testClass = methodSource.getJavaClass();
        Method testMethod = methodSource.getJavaMethod();
        TestEndpointType requiredEndpointType =
                EndpointConditionExtension.endpointOfMethod(testMethod, testClass);
        Set<ProtocolVersion> versionList = new HashSet<>();
        versionList.add(versionToCount);
        return TlsVersionCondition.versionsMatch(
                        versionList,
                        TlsVersionCondition.getSupportedTestVersions(testMethod, testClass))
                && requiredEndpointType != null
                && (executionTestEndpointType == TestEndpointType.BOTH
                        || requiredEndpointType == endpointTypeToCount
                        || executionTestEndpointType == endpointTypeToCount)
                && requiredEndpointType.isMatchingTestEndpointType(executionTestEndpointType);
    }

    /**
     * Logs, how many tests were discovered for every TLS version, as well as test strength and
     * connection timeout.
     *
     * @param testPlan the testPlan, supplied by JUnits discovery
     */
    public static void printTestInfo(TestPlan testPlan) {
        LOGGER.info("Scheduled test templates:");
        TestEndpointType executionEndpointType =
                TestContext.getInstance().getConfig().getTestEndpointMode();
        if (TestContext.getInstance().getConfig().isUseDTLS()) {
            long clientDtls12 =
                    testPlan.countTestIdentifiers(
                            i ->
                                    countTests(
                                            i,
                                            ProtocolVersion.DTLS12,
                                            TestEndpointType.CLIENT,
                                            executionEndpointType));
            long serverDtls12 =
                    testPlan.countTestIdentifiers(
                            i ->
                                    countTests(
                                            i,
                                            ProtocolVersion.DTLS12,
                                            TestEndpointType.SERVER,
                                            executionEndpointType));
            LOGGER.info(
                    "DTLS 1.2 tests: {} client tests, {} server tests", clientDtls12, serverDtls12);
        } else {
            long clientTls12 =
                    testPlan.countTestIdentifiers(
                            i ->
                                    countTests(
                                            i,
                                            ProtocolVersion.TLS12,
                                            TestEndpointType.CLIENT,
                                            executionEndpointType));
            long serverTls12 =
                    testPlan.countTestIdentifiers(
                            i ->
                                    countTests(
                                            i,
                                            ProtocolVersion.TLS12,
                                            TestEndpointType.SERVER,
                                            executionEndpointType));
            long clientTls13 =
                    testPlan.countTestIdentifiers(
                            i ->
                                    countTests(
                                            i,
                                            ProtocolVersion.TLS13,
                                            TestEndpointType.CLIENT,
                                            executionEndpointType));
            long serverTls13 =
                    testPlan.countTestIdentifiers(
                            i ->
                                    countTests(
                                            i,
                                            ProtocolVersion.TLS13,
                                            TestEndpointType.SERVER,
                                            executionEndpointType));
            LOGGER.info(
                    "TLS 1.2 tests: {} client tests, {} server tests", clientTls12, serverTls12);
            LOGGER.info(
                    "TLS 1.3 tests: {} client tests, {} server tests", clientTls13, serverTls13);
        }
        LOGGER.info(
                "Testing using default strength "
                        + TestContext.getInstance().getConfig().getAnvilTestConfig().getStrength());
        LOGGER.info(
                "Default timeout "
                        + TestContext.getInstance()
                                .getConfig()
                                .getAnvilTestConfig()
                                .getConnectionTimeout()
                        + " ms");
    }
}
